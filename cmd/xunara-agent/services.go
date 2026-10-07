package main

// This file implements `xunara-agent services`: publishing the services this
// node advertises (Xunara Atlas) over the native client protocol, and keeping
// the declaration that `xunara-agent run` reconciles.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/xunara/xunara/client/daemon"
	"github.com/xunara/xunara/client/protocol"
)

// The server enforces these limits (control/services.go); the CLI mirrors them
// so a declaration that cannot be published fails before a network round trip.
// The server remains the authority: a rule added there still rejects what an
// older agent accepts.
const (
	maxServicesPerNode         = 32
	maxServiceNameLen          = 63
	maxServiceMetadataEntries  = 16
	maxServiceMetadataKeyLen   = 64
	maxServiceMetadataValueLen = 256
	maxServiceMetadataBytes    = 2 << 10
	// maxServicesFileBytes bounds the declaration file; a declaration is tiny
	// (32 services at most), so anything larger is a mistake.
	maxServicesFileBytes = 1 << 20
)

// runServices implements `xunara-agent services`.
func runServices(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("services needs a subcommand: publish, list or clear")
	}
	switch args[0] {
	case "publish":
		return runServicesPublish(ctx, args[1:])
	case "list":
		return runServicesList(args[1:])
	case "clear":
		return runServicesClear(ctx, args[1:])
	default:
		return fmt.Errorf("unknown services subcommand %q", args[0])
	}
}

// runServicesPublish implements `xunara-agent services publish -file <file>`:
// it publishes the declaration in the file and saves it for `run` to keep
// published.
func runServicesPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("services publish", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	file := fs.String("file", "", "declaration file: {\"services\": [{\"name\": .., \"protocol\": .., \"port\": ..}]}")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("services publish needs -file")
	}

	services, err := readServicesFile(*file)
	if err != nil {
		return err
	}
	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}

	views, err := client.Services(ctx, state.Token, keys, services)
	if err != nil {
		return err
	}
	// Save the declaration only after the server accepted it: on any error
	// above, a running agent keeps publishing what was working before.
	if err := daemon.SaveServices(*stateDir, services); err != nil {
		return err
	}
	return writePublishedServices(os.Stdout, views)
}

// runServicesList implements `xunara-agent services list`: the local
// declaration, which is what this agent publishes.
func runServicesList(args []string) error {
	fs := flag.NewFlagSet("services list", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	asJSON := fs.Bool("json", false, "print the declaration as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	services, err := daemon.LoadServices(*stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stdout, "No services are declared on this agent.")
			fmt.Fprintln(os.Stdout, "Publish some with `xunara-agent services publish -file <file>`.")
			return nil
		}
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Services []protocol.Service `json:"services"`
		}{Services: services})
	}
	return writeDeclaredServices(os.Stdout, services)
}

// runServicesClear implements `xunara-agent services clear`: withdraw every
// service and stop `run` from re-publishing them.
func runServicesClear(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("services clear", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	if _, err := client.Services(ctx, state.Token, keys, nil); err != nil {
		return err
	}
	if err := daemon.RemoveServices(*stateDir); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "All services withdrawn.")
	return nil
}

// enrolledClient loads the agent's state and returns everything a call needs.
func enrolledClient(stateDir string) (daemon.State, protocol.Keys, *protocol.Client, error) {
	state, err := daemon.LoadState(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return daemon.State{}, protocol.Keys{}, nil, errors.New(
				"this agent is not enrolled; run `xunara-agent enroll -server <url>` first")
		}
		return daemon.State{}, protocol.Keys{}, nil, err
	}
	if !state.Enrolled() {
		return daemon.State{}, protocol.Keys{}, nil, errors.New(
			"this agent has not been approved yet; run `xunara-agent enroll` again after approving the device")
	}
	keys, err := state.Keys()
	if err != nil {
		return daemon.State{}, protocol.Keys{}, nil, err
	}
	return state, keys, protocol.New(state.ServerURL), nil
}

// serviceFile is the declaration file format, shared with the daemon:
// {"services": [{"name": "api", "protocol": "tcp", "port": 8080}]}.
type serviceFile struct {
	Services []protocol.Service `json:"services"`
}

// readServicesFile parses and validates a declaration file. Unknown fields are
// refused: a typo like "protcol" must not silently publish a service without
// its protocol.
func readServicesFile(path string) ([]protocol.Service, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading -file: %w", err)
	}
	if info.Size() > maxServicesFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxServicesFileBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading -file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var decl serviceFile
	if err := dec.Decode(&decl); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("parsing %s: trailing data after the declaration", path)
	}
	return normalizeServices(decl.Services)
}

// normalizeServices validates a declaration and returns the canonical form
// (protocols lowercased). Every rule is fail-closed: one bad entry rejects the
// whole file.
func normalizeServices(services []protocol.Service) ([]protocol.Service, error) {
	if len(services) > maxServicesPerNode {
		return nil, fmt.Errorf("at most %d services may be advertised per node", maxServicesPerNode)
	}

	out := make([]protocol.Service, 0, len(services))
	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if err := validateServiceName(svc.Name); err != nil {
			return nil, err
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("service name %q is listed twice", svc.Name)
		}
		seen[svc.Name] = true

		proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("service %q has an unsupported protocol %q", svc.Name, svc.Protocol)
		}
		if svc.Port == 0 || svc.Port > 65535 {
			return nil, fmt.Errorf("service %q has an invalid port", svc.Name)
		}
		metadata, err := validateServiceMetadata(svc.Metadata)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}

		out = append(out, protocol.Service{Name: svc.Name, Protocol: proto, Port: svc.Port, Metadata: metadata})
	}
	return out, nil
}

// validateServiceName enforces the DNS label shape a service name must have.
func validateServiceName(name string) error {
	if name == "" {
		return errors.New("service name is empty")
	}
	if len(name) > maxServiceNameLen {
		return fmt.Errorf("service name is longer than %d bytes", maxServiceNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return fmt.Errorf("service name %q must not start or end with a hyphen", name)
			}
		default:
			return fmt.Errorf("service name %q must be a lowercase DNS label", name)
		}
	}
	return nil
}

// validateServiceMetadata bounds and cleans one service's metadata: printable
// ASCII only, so terminal surfaces cannot be made to render escape sequences.
func validateServiceMetadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	if len(metadata) > maxServiceMetadataEntries {
		return nil, fmt.Errorf("metadata has more than %d entries", maxServiceMetadataEntries)
	}

	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if key == "" || len(key) > maxServiceMetadataKeyLen || !printableASCII(key, false) {
			return nil, fmt.Errorf("metadata key %q is invalid", sanitizeServiceName(key))
		}
		if len(value) > maxServiceMetadataValueLen || !printableASCII(value, true) {
			return nil, fmt.Errorf("metadata value of %q is invalid", sanitizeServiceName(key))
		}
		out[key] = value
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, errors.New("metadata cannot be encoded")
	}
	if len(encoded) > maxServiceMetadataBytes {
		return nil, fmt.Errorf("metadata is larger than %d bytes", maxServiceMetadataBytes)
	}
	return out, nil
}

// printableASCII reports whether s is printable ASCII. Space is only allowed
// when allowSpace is set (values may read as prose; keys may not).
func printableASCII(s string, allowSpace bool) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		if allowSpace && r == ' ' {
			continue
		}
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// sanitizeServiceName makes an untrusted name safe to echo back in an error
// message: printable ASCII only, bounded.
func sanitizeServiceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > unicode.MaxASCII || (r < 0x21 && r != ' ') || r == 0x7f {
			continue
		}
		if b.Len() >= 64 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// serviceRow is the common render shape of a stored service and a declared
// one; DNSName and Updated are only known for stored services.
type serviceRow struct {
	Name     string
	Protocol string
	Port     uint32
	DNSName  string
	Updated  time.Time
	Metadata map[string]string
}

// writePublishedServices renders the set the server stored after a publish.
func writePublishedServices(w io.Writer, views []protocol.ServiceView) error {
	rows := make([]serviceRow, 0, len(views))
	for _, view := range views {
		rows = append(rows, serviceRow{
			Name:     view.Name,
			Protocol: view.Protocol,
			Port:     uint32(view.Port),
			DNSName:  view.DNSName,
			Updated:  view.Updated,
			Metadata: view.Metadata,
		})
	}
	return writeServicesTable(w, rows, "No services are advertised by this node.")
}

// writeDeclaredServices renders the local declaration.
func writeDeclaredServices(w io.Writer, services []protocol.Service) error {
	rows := make([]serviceRow, 0, len(services))
	for _, svc := range services {
		rows = append(rows, serviceRow{Name: svc.Name, Protocol: svc.Protocol, Port: svc.Port, Metadata: svc.Metadata})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return writeServicesTable(w, rows, "No services are declared on this agent.")
}

// writeServicesTable renders services with their metadata. The DNS name and
// update time are only shown when at least one row carries them.
func writeServicesTable(w io.Writer, rows []serviceRow, empty string) error {
	if len(rows) == 0 {
		fmt.Fprintln(w, empty)
		return nil
	}

	stored := false
	for _, row := range rows {
		if row.DNSName != "" || !row.Updated.IsZero() {
			stored = true
			break
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if stored {
		fmt.Fprintln(tw, "NAME\tPROTO\tPORT\tDNS NAME\tUPDATED")
	} else {
		fmt.Fprintln(tw, "NAME\tPROTO\tPORT")
	}
	for _, row := range rows {
		if stored {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", row.Name, row.Protocol, row.Port,
				dashIfEmpty(row.DNSName), dashIfZeroTime(row.Updated))
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\n", row.Name, row.Protocol, row.Port)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, row := range rows {
		if len(row.Metadata) == 0 {
			continue
		}
		keys := make([]string, 0, len(row.Metadata))
		for key := range row.Metadata {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		fmt.Fprintf(w, "\n%s metadata:\n", row.Name)
		mt := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, key := range keys {
			fmt.Fprintf(mt, "  %s\t%s\n", key, row.Metadata[key])
		}
		if err := mt.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// dashIfEmpty renders an unknown value.
func dashIfEmpty(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// dashIfZeroTime renders a time the local declaration does not know.
func dashIfZeroTime(at time.Time) string {
	if at.IsZero() {
		return "-"
	}
	return at.Format("2006-01-02 15:04:05 MST")
}
