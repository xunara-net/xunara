package control

import (
	"net/http/httptest"
	"path"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestNodeSurvivesServerRestart is the durability contract of the control
// plane: a registered machine must come back online after a restart without a
// second login, using the same machine and node keys.
func TestNodeSurvivesServerRestart(t *testing.T) {
	dir := t.TempDir()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// --- first server lifetime: register and approve ---
	first := newServerAt(t, dir)
	firstHTTP := httptest.NewServer(first.Handler())

	conn := dialNoise(t, firstHTTP, machineKey)
	client := h2Client(conn)

	regResp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "durable"},
	}))
	if regResp.AuthURL == "" {
		t.Fatal("expected an AuthURL for the first registration")
	}
	if err := first.ApproveRegistration(path.Base(regResp.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}
	if resp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Followup: regResp.AuthURL,
	})); !resp.MachineAuthorized {
		t.Fatalf("registration not authorized: %+v", resp)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("closing session: %v", err)
	}
	firstHTTP.Close()
	if err := first.Close(); err != nil {
		t.Fatalf("closing first server: %v", err)
	}

	// --- second server lifetime: the node must still be known ---
	second := newServerAt(t, dir)
	secondHTTP := httptest.NewServer(second.Handler())
	defer secondHTTP.Close()

	conn2 := dialNoise(t, secondHTTP, machineKey)
	defer conn2.Close()
	client2 := h2Client(conn2)

	resp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client2, "/machine/register", tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}))
	if !resp.MachineAuthorized {
		t.Fatalf("node was not recognized after restart: %+v", resp)
	}
	if resp.User.ID != 1 {
		t.Errorf("user id = %d, want 1", resp.User.ID)
	}

	// The node must also be servable: its netmap still resolves.
	mapResp := decodeMapResponse(t, postRaw(t, client2, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if mapResp.Node == nil || mapResp.Node.Name != "durable." {
		t.Fatalf("self node after restart = %+v", mapResp.Node)
	}
}
