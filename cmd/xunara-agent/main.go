// Command xunara-agent is the Xunara native client: it enrolls this machine
// with a control plane and keeps it present over /api/agent/v1, the native
// client protocol. It never speaks TS2021, so it cannot affect official-client
// compatibility.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xunara/xunara/client/daemon"
	"github.com/xunara/xunara/client/protocol"
)

// authKeyEnv is where the pre-auth key comes from by default. The key is never
// taken from a flag: process arguments are readable by every user on the host
// (AGENTS.md section 8).
const authKeyEnv = "XUNARA_AGENT_AUTH_KEY"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "enroll":
		err = runEnroll(ctx, os.Args[2:])
	case "run":
		err = runAgent(ctx, os.Args[2:])
	case "status":
		err = runStatus(ctx, os.Args[2:])
	case "services":
		err = runServices(ctx, os.Args[2:])
	case "version":
		fmt.Println("xunara-agent", daemon.Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		var pending *daemon.PendingApprovalError
		if errors.As(err, &pending) {
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, "the request is recorded; approve it in the console, then rerun enroll")
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "xunara-agent:", err)
		os.Exit(1)
	}
}

// defaultStateDir returns the per-user state directory.
func defaultStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "xunara-agent")
	}
	return "xunara-agent-state"
}

// runEnroll implements `xunara-agent enroll`.
func runEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	serverURL := fs.String("server", "", "control server base URL, e.g. https://login.example.com")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for the agent's key material and credential")
	hostname := fs.String("hostname", "", "hostname to register (defaults to the OS hostname)")
	authKeyFile := fs.String("auth-key-file", "", "file containing a pre-auth key (0600 recommended)")
	ephemeral := fs.Bool("ephemeral", false, "register an ephemeral node")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for interactive approval")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" {
		return errors.New("enroll needs -server")
	}

	authKey := os.Getenv(authKeyEnv)
	if *authKeyFile != "" {
		raw, err := os.ReadFile(*authKeyFile)
		if err != nil {
			return fmt.Errorf("reading -auth-key-file: %w", err)
		}
		authKey = string(bytesTrimSpace(raw))
	}
	if authKey == "" {
		fmt.Fprintf(os.Stderr,
			"note: no pre-auth key (env %s or -auth-key-file); enrollment needs browser approval\n", authKeyEnv)
	}

	host, _ := os.Hostname()
	if *hostname != "" {
		host = *hostname
	}

	state, err := daemon.Enroll(ctx, daemon.EnrollOptions{
		ServerURL: daemon.NormalizeServerURL(*serverURL),
		StateDir:  *stateDir,
		AuthKey:   authKey,
		Hostname:  host,
		Ephemeral: *ephemeral,
		Timeout:   *timeout,
		Logger:    newLogger(*logLevel),
	})
	if err != nil {
		return err
	}

	fmt.Printf("enrolled node %d (%s) with %s\n", state.NodeID, state.StableID, state.ServerURL)
	fmt.Printf("state written to %s (0600)\n", filepath.Join(*stateDir, "agent.json"))
	return nil
}

// runAgent implements `xunara-agent run`: the steady-state loop.
func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	interval := fs.Duration("interval", 30*time.Second, "heartbeat/netmap interval")
	servicesInterval := fs.Duration("services-interval", 5*time.Minute, "how often to re-publish the service declaration")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logLevel)
	state, err := daemon.LoadState(*stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("this agent is not enrolled; run `xunara-agent enroll -server <url>` first")
		}
		return err
	}

	agent, err := daemon.NewAgent(state, nil, logger)
	if err != nil {
		return err
	}
	agent.Interval = *interval
	// The declaration file is re-read on every refresh, so a `services
	// publish` next to a running agent takes effect without a restart.
	agent.StateDir = *stateDir
	agent.ServicesInterval = *servicesInterval

	if !state.Enrolled() {
		return errors.New("this agent has not been approved yet; run `xunara-agent enroll` again after approving the device")
	}

	logger.Info("agent running", "server", state.ServerURL, "node_id", state.NodeID)
	return agent.Run(ctx)
}

// runStatus implements `xunara-agent status`.
func runStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	state, err := daemon.LoadState(*stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("this agent is not enrolled")
		}
		return err
	}

	agent, err := daemon.NewAgent(state, protocol.New(state.ServerURL), slog.Default())
	if err != nil {
		return err
	}
	if !state.Enrolled() {
		return errors.New("this agent has not been approved yet; run `xunara-agent enroll` again after approving the device")
	}

	status, err := agent.Status(ctx)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}

	fmt.Printf("server:   %s\n", status.ServerURL)
	fmt.Printf("node:     %d (%s)\n", status.NodeID, status.StableID)
	if status.Name != "" {
		fmt.Printf("name:     %s\n", status.Name)
	}
	fmt.Printf("peers:    %d\n", status.Peers)
	fmt.Printf("agent:    %s\n", status.Version)
	return nil
}

// usage prints the command overview.
func usage() {
	fmt.Fprint(os.Stderr, `xunara-agent — Xunara native client

usage:
  xunara-agent enroll -server <url> [-auth-key-file f] [-state-dir d] [-hostname h]
  xunara-agent run    [-state-dir d] [-interval 30s] [-services-interval 5m]
  xunara-agent status [-state-dir d] [-json]
  xunara-agent services publish -file <file> [-state-dir d]
  xunara-agent services list [-state-dir d] [-json]
  xunara-agent services clear [-state-dir d]
  xunara-agent version

The pre-auth key is read from the environment variable `+authKeyEnv+` or from
-auth-key-file; it is never accepted as a flag.

The services declaration file is
  {"services": [{"name": "api", "protocol": "tcp", "port": 443}]}
`)
}

// bytesTrimSpace trims ASCII whitespace from a credential file.
func bytesTrimSpace(raw []byte) []byte {
	start, end := 0, len(raw)
	for start < end && isSpace(raw[start]) {
		start++
	}
	for end > start && isSpace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
