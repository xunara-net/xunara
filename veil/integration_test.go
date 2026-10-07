package veil

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/control"
	"github.com/xunara/xunara/state"
)

// TestAdmissionAgainstControlPlane wires Veil to the real control plane
// admission endpoint and checks that registered node keys are admitted while
// unknown ones are rejected.
func TestAdmissionAgainstControlPlane(t *testing.T) {
	ctrl, err := control.New(control.Config{
		ServerURL: "http://login.test",
		StateDir:  t.TempDir(),
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	defer ctrl.Close()

	// A registered node: its key pair may connect.
	nodeKey := key.NewNode()
	node := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    nodeKey.Public(),
		Method:     state.RegisterMethodInteractive,
	}
	if err := ctrl.Store().CreateNode(&node); err != nil {
		t.Fatalf("creating node: %v", err)
	}

	ctrlHTTP := httptest.NewServer(ctrl.Handler())
	defer ctrlHTTP.Close()

	_, url := serveTestVeil(t, Config{VerifyURL: ctrlHTTP.URL + "/derp/admit"})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// The registered node is admitted.
	registered, err := derphttp.NewClient(nodeKey, url, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	defer registered.Close()
	if err := registered.Connect(ctx); err != nil {
		t.Fatalf("registered node was not admitted: %v", err)
	}

	// A node key the control plane does not know is rejected.
	stranger, err := derphttp.NewClient(key.NewNode(), url, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	defer stranger.Close()
	if err := stranger.Connect(ctx); err != nil {
		return
	}
	assertServerRejects(t, ctx, stranger)
}
