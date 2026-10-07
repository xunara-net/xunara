package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/identity"
)

// runUser implements "xunara user": inspecting and updating the trust plane's
// users.
func runUser(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: user requires a subcommand: list or update")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runUserList(args[1:])
	case "update":
		runUserUpdate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown user subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runUserList(args []string) {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()
	ids := openIdentity(store)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tLOGIN\tDISPLAY\tEMAIL\tIDENTITIES\tCREATED")
	for _, u := range ids.ListUsers() {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n",
			u.ID, u.LoginName, u.DisplayName, u.Email,
			len(ids.ListExternalIdentities(u.ID)), u.CreatedAt.Format(time.RFC3339))
	}
	w.Flush()
}

// lookupUser resolves a user reference that is either a numeric ID or a login
// name.
func lookupUser(ids identity.UserStore, ref string) (identity.User, bool) {
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return ids.GetUser(tailcfg.UserID(id))
	}
	return ids.GetUserByLoginName(ref)
}

func runUserUpdate(args []string) {
	fs := flag.NewFlagSet("user update", flag.ExitOnError)

	var (
		stateDir    = fs.String("state-dir", "data", "control server state directory")
		login       = fs.String("login", "", "new login name")
		displayName = fs.String("display-name", "", "new display name")
		email       = fs.String("email", "", "new email attribute")
	)
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr,
			"usage: xunara user update [-state-dir DIR] [-login LOGIN] [-display-name NAME] [-email EMAIL] <id|login>")
		os.Exit(2)
	}
	if *login == "" && *displayName == "" && *email == "" {
		fmt.Fprintln(os.Stderr, "xunara: user update needs at least one of -login, -display-name or -email")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()
	ids := openIdentity(store)

	user, ok := lookupUser(ids, fs.Arg(0))
	if !ok {
		fmt.Fprintf(os.Stderr, "xunara: user %q not found\n", fs.Arg(0))
		os.Exit(1)
	}

	var changes []string
	if *login != "" && *login != user.LoginName {
		changes = append(changes, "login")
		user.LoginName = *login
	}
	if *displayName != "" && *displayName != user.DisplayName {
		changes = append(changes, "display_name")
		user.DisplayName = *displayName
	}
	if *email != "" && *email != user.Email {
		changes = append(changes, "email")
		user.Email = *email
	}
	if len(changes) == 0 {
		fmt.Println("no changes")
		return
	}

	if err := ids.UpdateUser(user); err != nil {
		fatal("updating user", err)
	}
	appendAudit(store, identity.AuditUserUpdated, fmt.Sprintf("user:%d", user.ID),
		"updated "+strings.Join(changes, ", "))
	fmt.Printf("%d\t%s\t%s\t%s\n", user.ID, user.LoginName, user.DisplayName, user.Email)
}
