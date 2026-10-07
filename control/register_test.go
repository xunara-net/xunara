package control

import (
	"context"
	"errors"
	"net/http"
	"path"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/state"
)

func TestHandleRegisterInteractiveApproveThenReRegister(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	req := tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "n1"},
	}

	resp, err := s.handleRegister(context.Background(), req, mk)
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	if resp.MachineAuthorized {
		t.Fatal("first registration should not be authorized")
	}
	if resp.AuthURL == "" {
		t.Fatal("expected an AuthURL for interactive login")
	}

	if err := s.ApproveRegistration(path.Base(resp.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	req.Followup = resp.AuthURL
	resp2, err := s.handleRegister(context.Background(), req, mk)
	if err != nil {
		t.Fatalf("follow-up handleRegister: %v", err)
	}
	if !resp2.MachineAuthorized {
		t.Fatalf("follow-up not authorized: %+v", resp2)
	}

	node, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node was not created on approval")
	}
	if node.Hostname != "n1" {
		t.Errorf("hostname = %q, want n1", node.Hostname)
	}
	if node.MachineKey != mk {
		t.Error("node machine key does not match the registering session")
	}

	// A client restart re-registers with neither Auth nor Followup.
	resp3, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
	}, mk)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !resp3.MachineAuthorized {
		t.Fatalf("re-register not authorized: %+v", resp3)
	}
}

func TestHandleRegisterMachineKeyMismatch(t *testing.T) {
	s := newTestServer(t)

	nk := key.NewNode().Public()
	node := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    nk,
		Method:     state.RegisterMethodInteractive,
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("seeding node: %v", err)
	}

	_, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
	}, key.NewMachine().Public())

	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v, want 401 HTTPError", err)
	}
}

func TestHandleRegisterLogout(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	node := state.Node{MachineKey: mk, NodeKey: nk, Method: state.RegisterMethodInteractive}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("seeding node: %v", err)
	}

	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
		Expiry:  time.Now().Add(-time.Hour),
	}, mk)
	if err != nil {
		t.Fatalf("logout handleRegister: %v", err)
	}
	if resp.NodeKeyExpired && !resp.MachineAuthorized && resp.Error != "" {
		t.Fatalf("unexpected error response: %+v", resp)
	}
	if _, ok := s.store.GetNodeByNodeKey(nk); ok {
		t.Fatal("node should be removed after logout")
	}
}
