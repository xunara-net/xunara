package daemon

import (
	"context"
	"errors"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/xunara/xunara/client/protocol"
	"github.com/xunara/xunara/control"
	"github.com/xunara/xunara/state"
)

// startControlServer brings up a real control plane for the native-client
// tests.
func startControlServer(t *testing.T) (*control.Server, *httptest.Server) {
	t.Helper()

	srv, err := control.New(control.Config{
		StateDir:  t.TempDir(),
		ServerURL: "http://login.test",
		Domain:    "example.com",
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return srv, hs
}

// seedPreAuthKey creates a pre-auth key on the control plane.
func seedPreAuthKey(t *testing.T, srv *control.Server) string {
	t.Helper()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		t.Fatalf("NewPreAuthKeySecret: %v", err)
	}
	key := state.PreAuthKey{Key: secret, UserID: state.DefaultUserID}
	if err := srv.Store().CreatePreAuthKey(&key); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	return secret
}

// heartbeatFor builds the heartbeat body for a node identity.
func heartbeatFor(t *testing.T, keys protocol.Keys) protocol.HeartbeatRequest {
	t.Helper()
	return protocol.HeartbeatRequest{
		MachineKey:   keys.Machine.Public().String(),
		NodeKey:      keys.Node.Public().String(),
		Hostname:     "e2e-agent",
		AgentVersion: Version,
	}
}

// TestAgentEndToEndEnrollHeartbeatStatus drives the native client against a
// real control plane: enrollment, heartbeat, status (netmap) and the node's
// presence in the server store.
func TestAgentEndToEndEnrollHeartbeatStatus(t *testing.T) {
	srv, hs := startControlServer(t)
	secret := seedPreAuthKey(t, srv)

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		AuthKey:   secret,
		Hostname:  "e2e-agent",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if state.NodeID == 0 || state.StableID == "" {
		t.Fatalf("enrolled state = %+v", state)
	}

	nodes := srv.Store().ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("control plane has %d nodes, want 1", len(nodes))
	}
	if nodes[0].Hostname != "e2e-agent" {
		t.Errorf("node hostname = %q, want e2e-agent", nodes[0].Hostname)
	}

	agent, err := NewAgent(state, nil, nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}

	status, err := agent.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.HasPrefix(status.Name, "e2e-agent.") {
		t.Errorf("status name = %q, want the MagicDNS name", status.Name)
	}
	if status.NodeID != state.NodeID {
		t.Errorf("status node ID = %d, want %d", status.NodeID, state.NodeID)
	}

	// A heartbeat reports liveness; the control plane must show the node
	// online even though it holds no Noise session.
	keys, err := state.Keys()
	if err != nil {
		t.Fatalf("state keys: %v", err)
	}
	if err := agent.Client.Heartbeat(context.Background(), state.Token, heartbeatFor(t, keys)); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !srv.IsNodeOnline(nodes[0].ID) {
		t.Error("node is not online after the agent heartbeat")
	}

	// Re-enrolling after the node was deleted fails closed: the state is gone
	// from the control plane and the agent must start over.
	if err := srv.Store().DeleteNode(nodes[0].ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if err := agent.Client.Heartbeat(context.Background(), state.Token, heartbeatFor(t, keys)); err == nil {
		t.Error("heartbeat with a deleted node succeeded")
	}
}

// TestAgentEndToEndInteractiveApproval drives the browser-approval path
// against the real device authorization store.
func TestAgentEndToEndInteractiveApproval(t *testing.T) {
	srv, hs := startControlServer(t)

	stateDir := t.TempDir()
	_, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		Hostname:  "approval-agent",
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("Enroll error = %v, want PendingApprovalError", err)
	}

	authID := path.Base(pending.AuthURL)
	if err := srv.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		Hostname:  "approval-agent",
	})
	if err != nil {
		t.Fatalf("post-approval Enroll: %v", err)
	}
	if state.Token == "" || state.NodeID == 0 {
		t.Fatalf("post-approval state = %+v", state)
	}

	agent, err := NewAgent(state, nil, nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if _, err := agent.Status(context.Background()); err != nil {
		t.Fatalf("Status after approval: %v", err)
	}
}
