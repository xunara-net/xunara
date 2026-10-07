// Package daemon runs a Xunara Agent: enrollment, credential storage, and the
// heartbeat/netmap loop that keeps the node present in the control plane.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/client/protocol"
)

// Version is the agent's own version, reported to the control plane.
const Version = "0.1.0"

// stateFile is the durable agent state inside the state directory.
const stateFile = "agent.json"

// defaultInterval is how often the agent heartbeats and refreshes its netmap.
const defaultInterval = 30 * time.Second

// maxInterval bounds the exponential backoff after server errors.
const maxInterval = 5 * time.Minute

// State is the agent's durable identity and credential.
//
// The machine and node keys are private key material: the file is written
// 0600 and never logged.
type State struct {
	ServerURL    string    `json:"server_url"`
	MachineKey   string    `json:"machine_key"`
	NodeKey      string    `json:"node_key"`
	Token        string    `json:"token"`
	NodeID       int64     `json:"node_id"`
	StableID     string    `json:"stable_id"`
	AgentVersion string    `json:"agent_version,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
}

// Keys parses the state's private keys.
func (s State) Keys() (protocol.Keys, error) {
	var machine key.MachinePrivate
	if err := machine.UnmarshalText([]byte(s.MachineKey)); err != nil {
		return protocol.Keys{}, fmt.Errorf("daemon: invalid machine key in state: %w", err)
	}
	var node key.NodePrivate
	if err := node.UnmarshalText([]byte(s.NodeKey)); err != nil {
		return protocol.Keys{}, fmt.Errorf("daemon: invalid node key in state: %w", err)
	}
	return protocol.Keys{Machine: machine, Node: node}, nil
}

// LoadState reads the agent state, returning [os.ErrNotExist] wrapped when the
// agent has not enrolled yet.
func LoadState(stateDir string) (State, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, stateFile))
	if err != nil {
		return State{}, err
	}

	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("daemon: parsing %s: %w", stateFile, err)
	}
	if s.ServerURL == "" || s.MachineKey == "" || s.NodeKey == "" {
		return State{}, errors.New("daemon: agent state is incomplete; enroll again")
	}
	return s, nil
}

// SaveState writes the agent state atomically with 0600 permissions.
func SaveState(stateDir string, s State) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("daemon: creating state directory: %w", err)
	}

	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("daemon: encoding state: %w", err)
	}

	final := filepath.Join(stateDir, stateFile)
	tmp, err := os.CreateTemp(stateDir, stateFile+".tmp*")
	if err != nil {
		return fmt.Errorf("daemon: creating state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("daemon: setting state file permissions: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("daemon: writing state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("daemon: closing state file: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("daemon: replacing state file: %w", err)
	}
	return nil
}

// EnrollOptions are the inputs to [Enroll].
type EnrollOptions struct {
	ServerURL string
	StateDir  string
	// AuthKey authorizes the machine without a browser. Empty starts the
	// interactive flow, which [Enroll] completes only if a human approves
	// within the timeout.
	AuthKey   string
	Hostname  string
	Ephemeral bool
	// Timeout bounds the interactive approval wait. Zero uses five minutes.
	Timeout time.Duration
	Logger  *slog.Logger
	// Client overrides the protocol client (tests).
	Client *protocol.Client
}

// Enroll registers this agent and persists the resulting state. With an auth
// key it returns immediately; otherwise it polls until the device is approved
// or timeout elapses.
func Enroll(ctx context.Context, opts EnrollOptions) (State, error) {
	if opts.ServerURL == "" {
		return State{}, errors.New("daemon: no server URL")
	}
	if opts.StateDir == "" {
		return State{}, errors.New("daemon: no state directory")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	client := opts.Client
	if client == nil {
		client = protocol.New(opts.ServerURL)
	}

	state, err := LoadState(opts.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	if state.MachineKey == "" {
		machine := key.NewMachine()
		node := key.NewNode()
		machineText, err := machine.MarshalText()
		if err != nil {
			return State{}, fmt.Errorf("daemon: encoding machine key: %w", err)
		}
		nodeText, err := node.MarshalText()
		if err != nil {
			return State{}, fmt.Errorf("daemon: encoding node key: %w", err)
		}
		state = State{
			ServerURL:  opts.ServerURL,
			MachineKey: string(machineText),
			NodeKey:    string(nodeText),
		}
	}
	if state.ServerURL != opts.ServerURL {
		return State{}, fmt.Errorf("daemon: state belongs to %s, not %s", state.ServerURL, opts.ServerURL)
	}

	// Persist the generated keys before talking to the server: a pending
	// interactive enrollment must be retried with the same keys, or every
	// retry would create another device authorization.
	if err := SaveState(opts.StateDir, state); err != nil {
		return State{}, err
	}

	keys, err := state.Keys()
	if err != nil {
		return State{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	for {
		resp, err := client.Enroll(ctx, protocol.EnrollRequest{
			AuthKey:      opts.AuthKey,
			MachineKey:   keys.Machine.Public().String(),
			NodeKey:      keys.Node.Public().String(),
			Hostname:     opts.Hostname,
			OS:           runtime.GOOS,
			AgentVersion: Version,
			Ephemeral:    opts.Ephemeral,
		})
		if err != nil {
			return State{}, err
		}

		switch resp.Status {
		case "authorized":
			if resp.Token == "" {
				return State{}, errors.New("daemon: server authorized the agent without a token")
			}
			state.Token = resp.Token
			state.NodeID = resp.NodeID
			state.StableID = resp.StableID
			state.AgentVersion = Version
			state.EnrolledAt = time.Now().UTC()
			if err := SaveState(opts.StateDir, state); err != nil {
				return State{}, err
			}
			return state, nil
		case "pending":
			opts.Logger.Info("waiting for device approval", "url", resp.AuthURL)
			// Interactive enrollment: no auth key was supplied, so the agent
			// exits and the operator approves and reruns it.
			return state, &PendingApprovalError{AuthURL: resp.AuthURL}
		case "rejected":
			return State{}, fmt.Errorf("daemon: enrollment rejected: %s", resp.Error)
		default:
			return State{}, fmt.Errorf("daemon: unknown enrollment status %q", resp.Status)
		}
	}
}

// PendingApprovalError means the device needs a human to approve it in the
// browser; running enroll again afterwards authorizes the agent.
type PendingApprovalError struct {
	AuthURL string
}

func (e *PendingApprovalError) Error() string {
	return "daemon: device approval pending; approve it at " + e.AuthURL + " and run enroll again"
}

// Agent runs the steady-state loop on top of a persisted [State].
type Agent struct {
	State    State
	Interval time.Duration
	Logger   *slog.Logger
	Client   *protocol.Client

	// lastNetmap is the most recent netmap the server sent; guarded by the
	// loop itself (Status is only called from the same goroutine in tests) and
	// published for status reporting.
	lastNetmap *tailcfg.MapResponse
}

// NewAgent builds the steady-state loop for an enrolled state.
func NewAgent(state State, client *protocol.Client, logger *slog.Logger) (*Agent, error) {
	if _, err := state.Keys(); err != nil {
		return nil, err
	}
	if client == nil {
		client = protocol.New(state.ServerURL)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{State: state, Interval: defaultInterval, Logger: logger, Client: client}, nil
}

// Run heartbeats and refreshes the netmap until ctx is cancelled. Server
// errors back off exponentially. A revoked credential stops the loop: retrying
// with a dead token would only fill the audit log.
func (a *Agent) Run(ctx context.Context) error {
	keys, err := a.State.Keys()
	if err != nil {
		return err
	}

	interval := a.Interval
	if interval <= 0 {
		interval = defaultInterval
	}

	for {
		err := a.tick(ctx, keys)
		switch {
		case err == nil:
			interval = a.Interval
			if interval <= 0 {
				interval = defaultInterval
			}
		case protocol.IsUnauthorized(err):
			return fmt.Errorf("daemon: credential rejected (%w); enroll again", err)
		default:
			a.Logger.Warn("agent cycle failed", "err", err)
			interval *= 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// tick performs one heartbeat + netmap refresh.
func (a *Agent) tick(ctx context.Context, keys protocol.Keys) error {
	hostname, _ := os.Hostname()
	if err := a.Client.Heartbeat(ctx, a.State.Token, protocol.HeartbeatRequest{
		MachineKey:   keys.Machine.Public().String(),
		NodeKey:      keys.Node.Public().String(),
		Hostname:     hostname,
		AgentVersion: Version,
	}); err != nil {
		return err
	}

	netmap, err := a.Client.Netmap(ctx, a.State.Token, keys)
	if err != nil {
		return err
	}
	a.lastNetmap = netmap

	if netmap.Node != nil {
		a.Logger.Debug("netmap refreshed",
			"node", netmap.Node.Name, "peers", len(netmap.Peers))
	}
	return nil
}

// Status summarizes the agent for `xunara-agent status`.
type Status struct {
	NodeID    int64  `json:"node_id"`
	StableID  string `json:"stable_id"`
	ServerURL string `json:"server_url"`
	Version   string `json:"agent_version"`
	// Name is the node's MagicDNS name, empty when the agent has not fetched a
	// netmap yet.
	Name  string `json:"name,omitempty"`
	Peers int    `json:"peers,omitempty"`
}

// Status reports what the agent knows after at least one cycle. Run it after
// [Agent.tick]-equivalent work: it fetches a fresh netmap.
func (a *Agent) Status(ctx context.Context) (Status, error) {
	keys, err := a.State.Keys()
	if err != nil {
		return Status{}, err
	}
	netmap, err := a.Client.Netmap(ctx, a.State.Token, keys)
	if err != nil {
		return Status{}, err
	}

	status := Status{
		NodeID:    a.State.NodeID,
		StableID:  a.State.StableID,
		ServerURL: a.State.ServerURL,
		Version:   Version,
		Peers:     len(netmap.Peers),
	}
	if netmap.Node != nil {
		status.Name = netmap.Node.Name
	}
	return status, nil
}

// Enrolled reports whether the state carries a usable credential.
func (s State) Enrolled() bool { return s.Token != "" }

// CleanState removes the local agent state (used by `enroll --force` and
// tests). It does not touch the control plane.
func CleanState(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// NormalizeServerURL trims a trailing slash.
func NormalizeServerURL(raw string) string { return strings.TrimRight(raw, "/") }
