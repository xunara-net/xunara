// Command xunara is the Xunara administration CLI.
//
// It operates on the control server's state directory directly, so it must run
// where that directory is reachable (same host, or a shared filesystem). A
// network admin API arrives with the Platform milestone.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "preauthkey", "pak":
		runPreAuthKey(os.Args[2:])
	case "routes":
		runRoutes(os.Args[2:])
	case "dns":
		runDNS(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "user":
		runUser(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: xunara <command> [options]

Commands:
  preauthkey create    Create a pre-authentication key
  preauthkey list      List pre-authentication keys
  preauthkey delete    Delete a pre-authentication key
  routes list          List subnet routes and their approval state
  routes approve       Approve subnet routes (or exit-node routes) for a node
  routes unapprove     Withdraw approval for subnet routes
  dns list             List MagicDNS records published through set-dns
  dns delete           Delete a MagicDNS record by ID (or -all)
  policy check         Validate an ACL policy document and run its tests
  user list            List users in the trust plane
  user update          Change a user's login name, display name or email
  audit list           Show the control plane audit log

Run "xunara <command> -h" for command options.
`)
}

func runPreAuthKey(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: preauthkey requires a subcommand: create, list or delete")
		os.Exit(2)
	}

	switch args[0] {
	case "create":
		runCreate(args[1:])
	case "list":
		runList(args[1:])
	case "delete":
		runDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown preauthkey subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runCreate(args []string) {
	fs := flag.NewFlagSet("preauthkey create", flag.ExitOnError)

	var (
		stateDir  = fs.String("state-dir", "data", "control server state directory")
		userID    = fs.Uint64("user", uint64(state.DefaultUserID), "user ID the key authorizes nodes for")
		reusable  = fs.Bool("reusable", false, "allow the key to authorize more than one node")
		ephemeral = fs.Bool("ephemeral", false, "mark nodes authorized by this key as ephemeral")
		expiry    = fs.Duration("expiry", 0, "key lifetime, e.g. 24h (0 means no expiry)")
	)
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		fatal("generating key", err)
	}

	key := state.PreAuthKey{
		Key:       secret,
		UserID:    tailcfg.UserID(*userID),
		Reusable:  *reusable,
		Ephemeral: *ephemeral,
	}
	if *expiry > 0 {
		key.Expiry = time.Now().Add(*expiry).UTC()
	}

	if err := store.CreatePreAuthKey(&key); err != nil {
		fatal("storing key", err)
	}

	appendAudit(store, identity.AuditPreAuthKeyCreated, fmt.Sprintf("preauthkey:%d", key.ID),
		fmt.Sprintf("user=%d reusable=%t ephemeral=%t expiry=%s",
			key.UserID, key.Reusable, key.Ephemeral, formatTime(key.Expiry)))
	fmt.Println(key.Key)
}

func runList(args []string) {
	fs := flag.NewFlagSet("preauthkey list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	keys := store.ListPreAuthKeys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tKEY\tUSER\tREUSABLE\tEPHEMERAL\tUSED\tEXPIRY\tCREATED")

	for _, k := range keys {
		fmt.Fprintf(w, "%d\t%s\t%d\t%t\t%t\t%t\t%s\t%s\n",
			k.ID, k.Key, k.UserID, k.Reusable, k.Ephemeral, k.Used,
			formatTime(k.Expiry), k.Created.Format(time.RFC3339))
	}
	w.Flush()
}

func runDelete(args []string) {
	fs := flag.NewFlagSet("preauthkey delete", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xunara preauthkey delete [-state-dir DIR] <key>")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()

	var keyID uint64
	for _, k := range store.ListPreAuthKeys() {
		if k.Key == fs.Arg(0) {
			keyID = k.ID
			break
		}
	}
	if err := store.DeletePreAuthKey(fs.Arg(0)); err != nil {
		fatal("deleting key", err)
	}
	if keyID != 0 {
		appendAudit(store, identity.AuditPreAuthKeyDeleted, fmt.Sprintf("preauthkey:%d", keyID),
			"key deleted")
	}
}

func openStore(stateDir string) *state.SQLiteStore {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fatal("creating state directory", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := state.OpenSQLite(ctx, filepath.Join(stateDir, "state.db"))
	if err != nil {
		fatal("opening state", err)
	}
	return store
}

// openIdentity opens the trust plane on the same database as the state store.
func openIdentity(store *state.SQLiteStore) *identity.SQLiteStore {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s, err := identity.NewSQLiteStore(ctx, store.DB())
	if err != nil {
		fatal("opening identity store", err)
	}
	return s
}

// appendAudit records an administrative CLI action.
//
// A failed audit write is reported but does not fail the command: the action
// itself has already happened, and lying about its success would be worse.
func appendAudit(store *state.SQLiteStore, action, target, detail string) {
	event := identity.AuditEvent{Actor: "cli", Action: action, Target: target, Detail: detail}
	if err := openIdentity(store).AppendAudit(&event); err != nil {
		fmt.Fprintf(os.Stderr, "xunara: warning: writing audit event %s: %v\n", action, err)
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "xunara: %s: %v\n", what, err)
	os.Exit(1)
}
