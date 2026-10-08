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
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xunara/xunara/client/catalog"
	"github.com/xunara/xunara/client/daemon"
	"github.com/xunara/xunara/client/protocol"
)

// maxServicesFileBytes bounds the declaration file; a declaration is tiny
// (protocol.MaxServicesPerNode services at most), so anything larger is a
// mistake.
const maxServicesFileBytes = 1 << 20

// runServices implements `xunara-agent services`.
func runServices(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("services needs a subcommand: publish, import, list or clear")
	}
	switch args[0] {
	case "publish":
		return runServicesPublish(ctx, args[1:])
	case "import":
		return runServicesImport(ctx, args[1:])
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
	return publishDeclaration(ctx, *stateDir, services)
}

// consulTokenEnv is where the Consul ACL token comes from: like the Xunara
// pre-auth key it is never accepted as a flag, because process arguments are
// readable by every user on the host (AGENTS.md section 8). Consul's own
// tooling reads the same variable.
const consulTokenEnv = "CONSUL_HTTP_TOKEN"

// consulAddressEnv mirrors Consul's own variable for the agent address.
const consulAddressEnv = "CONSUL_HTTP_ADDR"

// runServicesImport implements `xunara-agent services import -from consul`: it
// maps the services registered on the local Consul agent into a declaration
// and publishes it (or prints it with -dry-run).
func runServicesImport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("services import", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	from := fs.String("from", "", "catalog to import from; only \"consul\" is supported")
	consulAddr := fs.String("consul-addr", "", "local Consul agent address (default $"+consulAddressEnv+", else "+catalog.DefaultConsulAddress+")")
	dryRun := fs.Bool("dry-run", false, "print the declaration as JSON instead of publishing it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from != "consul" {
		return fmt.Errorf("services import needs -from consul (got %q)", *from)
	}

	address := *consulAddr
	if address == "" {
		address = os.Getenv(consulAddressEnv)
	}
	services, warnings, err := catalog.ConsulServices(ctx, catalog.ConsulConfig{
		Address: address,
		Token:   os.Getenv(consulTokenEnv),
	})
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "xunara-agent: consul:", warning)
	}
	if err != nil {
		return err
	}
	if len(services) == 0 {
		// An empty declaration withdraws every service; make sure that is a
		// decision the operator can see, not a side effect of an empty or
		// ACL-scoped catalog.
		fmt.Fprintln(os.Stderr, "xunara-agent: warning: the Consul agent advertised no importable services")
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "xunara-agent: imported %d services from Consul\n", len(services))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(serviceFile{Services: services})
	}
	return publishDeclaration(ctx, *stateDir, services)
}

// publishDeclaration sends a declaration and, only when the server accepted
// it, saves it for `run` to keep published.
func publishDeclaration(ctx context.Context, stateDir string, services []protocol.Service) error {
	state, keys, client, err := enrolledClient(stateDir)
	if err != nil {
		return err
	}

	views, err := client.Services(ctx, state.Token, keys, services)
	if err != nil {
		return err
	}
	// Save the declaration only after the server accepted it: on any error
	// above, a running agent keeps publishing what was working before.
	if err := daemon.SaveServices(stateDir, services); err != nil {
		return err
	}
	writeHealthHint(services)
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
	return protocol.ValidateServices(decl.Services)
}

// serviceRow is the common render shape of a stored service and a declared
// one; DNSName, Updated and the reported Health are only known for stored
// services (a declaration only records that health is tracked).
type serviceRow struct {
	Name     string
	Protocol string
	Port     uint32
	DNSName  string
	Health   string
	Updated  time.Time
	Metadata map[string]string
}

// writeHealthHint tells the operator where a health-tracked service's
// readiness comes from. Without the file the service stays withdrawn from
// discovery, so the message is guidance, not a warning.
func writeHealthHint(services []protocol.Service) {
	names := make([]string, 0, len(services))
	for _, svc := range services {
		if svc.Health {
			names = append(names, svc.Name)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr, "xunara-agent: %s report readiness in <state-dir>/%s; `run` sends the report every -services-health-interval and the control plane withdraws unreported services\n",
		strings.Join(names, ", "), daemon.ServiceHealthFileName)
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
			Health:   view.Health,
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
		row := serviceRow{Name: svc.Name, Protocol: svc.Protocol, Port: svc.Port, Metadata: svc.Metadata}
		if svc.Health {
			row.Health = "tracked"
		}
		rows = append(rows, row)
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
	tracked := false
	for _, row := range rows {
		if row.DNSName != "" || !row.Updated.IsZero() {
			stored = true
		}
		if row.Health != "" {
			tracked = true
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := []string{"NAME", "PROTO", "PORT"}
	if stored {
		header = append(header, "DNS NAME", "UPDATED")
	}
	if tracked {
		header = append(header, "HEALTH")
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		fields := []string{row.Name, row.Protocol, strconv.FormatUint(uint64(row.Port), 10)}
		if stored {
			fields = append(fields, dashIfEmpty(row.DNSName), dashIfZeroTime(row.Updated))
		}
		if tracked {
			fields = append(fields, dashIfEmpty(row.Health))
		}
		fmt.Fprintln(tw, strings.Join(fields, "\t"))
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
