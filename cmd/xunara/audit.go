package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// runAudit implements "xunara audit": reading the control plane audit log.
func runAudit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: audit requires a subcommand: list")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runAuditList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown audit subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runAuditList(args []string) {
	fs := flag.NewFlagSet("audit list", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
		limit    = fs.Int("limit", 50, "show at most this many events (0 means all)")
	)
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTIME\tACTOR\tACTION\tTARGET\tDETAIL")
	for _, e := range openIdentity(store).ListAudit(*limit) {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			e.ID, e.Time.Format("2006-01-02 15:04:05"), e.Actor, e.Action, e.Target, e.Detail)
	}
	w.Flush()
}
