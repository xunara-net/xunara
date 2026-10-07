package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"tailscale.com/tka"
)

// runTKA implements "xunara tka": inspecting the tailnet's key authority.
func runTKA(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: tka requires a subcommand: status")
		os.Exit(2)
	}

	switch args[0] {
	case "status":
		runTKAStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown tka subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runTKAStatus implements "xunara tka status".
//
// The command is read-only by design. Initializing, disabling or signing with
// tailnet lock are protocol operations driven by a holder of a network-lock
// key through the client (`tailscale lock ...`); they need that private key,
// which the control plane never holds (AGENTS.md sections 5 and 8). What an
// operator needs locally is the state of the authority: on, off, which chain
// head, and how many nodes are actually signed.
func runTKAStatus(args []string) {
	fs := flag.NewFlagSet("tka status", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
	)
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	meta := store.TKAMeta()
	head, err := readTKAHead(filepath.Join(*stateDir, "tka"))
	if err != nil {
		fatal("reading the tailnet-lock store", err)
	}

	nodes := store.ListNodes()
	signed := 0
	for _, n := range nodes {
		if len(n.KeySignature) > 0 {
			signed++
		}
	}

	state := "never enabled"
	switch {
	case meta.Enabled:
		state = "enabled"
	case meta.Disabled:
		state = "disabled"
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "STATE\t%s\n", state)
	fmt.Fprintf(w, "EVER ENABLED\t%t\n", meta.EverEnabled)
	fmt.Fprintf(w, "DISABLED\t%t\n", meta.Disabled)
	if head != "" {
		fmt.Fprintf(w, "HEAD\t%s\n", head)
	}
	fmt.Fprintf(w, "NODES\t%d total, %d signed, %d unsigned\n", len(nodes), signed, len(nodes)-signed)
	w.Flush()

	// Cross-check the bookkeeping against what is on disk. The two can only
	// disagree if the state directory was edited out of band (a partial
	// restore, a hand-edited database); an operator should hear about that
	// rather than trust a half-restored deployment.
	switch {
	case meta.Enabled && head == "":
		fmt.Fprintln(os.Stderr, "xunara: warning: tailnet lock is enabled but no chain was found under the state directory")
	case !meta.EverEnabled && head != "":
		fmt.Fprintln(os.Stderr, "xunara: warning: a chain exists but the database says tailnet lock was never enabled")
	}
}

// readTKAHead returns the current head AUM hash, or "" when dir holds no
// chain.
//
// It reads through upstream's tailchonk implementation, so the CLI sees exactly
// the chain the server serves. Nothing is created or written: a missing state
// directory is reported as "no chain", not as an error.
func readTKAHead(dir string) (string, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	chonk, err := tka.ChonkDir(dir)
	if err != nil {
		return "", err
	}
	heads, err := chonk.Heads()
	if err != nil {
		return "", err
	}
	if len(heads) == 0 {
		return "", nil
	}
	authority, err := tka.Open(chonk)
	if err != nil {
		return "", err
	}
	return authority.Head().String(), nil
}
