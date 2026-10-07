package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

// TestTS2021HandshakeRegisterAndMap drives the server through a real TS2021
// Noise handshake (via the upstream client transport) and then exercises the
// machine-control API over the encrypted connection. This is the compatibility
// test the project exists for: if an official client can handshake here, the
// transport layer is compatible.
func TestTS2021HandshakeRegisterAndMap(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "interop")
	defer conn.Close()

	mapResp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	if mapResp.Node == nil {
		t.Fatal("map response has no self node")
	}
	if mapResp.Node.Key != nodeKey.Public() {
		t.Errorf("self node key = %v, want %v", mapResp.Node.Key, nodeKey.Public())
	}
	if mapResp.Node.Name != "interop." {
		t.Errorf("self node name = %q, want interop.", mapResp.Node.Name)
	}
	if len(mapResp.Node.Addresses) == 0 {
		t.Error("self node has no addresses")
	}
	if mapResp.Node.Online == nil || !*mapResp.Node.Online {
		t.Error("self node should be reported online")
	}
	if mapResp.Node.Cap != tailcfg.CurrentCapabilityVersion {
		t.Errorf("self node cap = %d, want %d", mapResp.Node.Cap, tailcfg.CurrentCapabilityVersion)
	}
	if _, ok := mapResp.PacketFilters["base"]; !ok {
		t.Error("map response is missing the base packet filter")
	}
}

// TestNetmapPushesPeerChanges checks the long-poll contract: a node's stream
// receives a fresh netmap when another node joins the tailnet.
func TestNetmapPushesPeerChanges(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "node-a")
	defer connA.Close()

	// Node B registers but is not approved yet, so it must not be visible.
	connB, _, _, authIDB := startRegistration(t, hs, "node-b")
	defer connB.Close()

	sess := openMapSession(t, clientA, nodeKeyA.Public())
	defer sess.Body.Close()

	first := readMapResponse(t, sess.Body)
	if len(first.Peers) != 0 {
		t.Fatalf("peers before approval = %d, want 0", len(first.Peers))
	}

	if err := s.ApproveRegistration(authIDB); err != nil {
		t.Fatalf("approving node B: %v", err)
	}

	second := readMapResponse(t, sess.Body)
	if len(second.Peers) != 1 {
		t.Fatalf("peers after approval = %d, want 1", len(second.Peers))
	}
	if got := second.Peers[0].Name; got != "node-b." {
		t.Errorf("peer name = %q, want node-b.", got)
	}
	if second.Peers[0].Online == nil || *second.Peers[0].Online {
		t.Error("node B has never polled, so it must not be online")
	}
}

// TestMapUnknownNodeStreamingSignalsExpired checks that a client asking for the
// netmap of an unknown node is told 404 rather than served a bogus netmap.
func TestMapUnknownNodeStreamingSignalsExpired(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	defer conn.Close()

	client := h2Client(conn)

	_, status := postRawStatus(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	})
	if status != http.StatusNotFound {
		t.Errorf("non-streaming unknown node status = %d, want 404", status)
	}
}

// TestWriteMapResponseFraming pins the on-wire framing: a 4-byte little-endian
// length prefix followed by the (optionally zstd-compressed) JSON body.
func TestWriteMapResponseFraming(t *testing.T) {
	rec := httptest.NewRecorder()

	msg := &tailcfg.MapResponse{KeepAlive: true}
	if err := writeMapResponse(rec, "zstd", false, msg); err != nil {
		t.Fatalf("writeMapResponse: %v", err)
	}

	body := rec.Body.Bytes()
	if len(body) < reservedResponseHeaderSize {
		t.Fatalf("body too short: %d", len(body))
	}
	n := binary.LittleEndian.Uint32(body[:reservedResponseHeaderSize])
	payload := body[reservedResponseHeaderSize:]
	if int(n) != len(payload) {
		t.Fatalf("length prefix = %d, payload = %d", n, len(payload))
	}

	decoded, err := zstdframe.AppendDecode(nil, payload)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}

	var got tailcfg.MapResponse
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if !got.KeepAlive {
		t.Error("decoded response is not a keep-alive")
	}
}

// startRegistration begins an interactive registration for a new node over a
// real Noise session, returning the live connection, the single HTTP/2 client
// bound to it, its node key and the pending auth ID.
func startRegistration(t *testing.T, hs *httptest.Server, hostname string) (net.Conn, *http.Client, key.NodePrivate, string) {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	client := h2Client(conn)

	regResp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}))
	if regResp.MachineAuthorized {
		t.Fatal("first registration must not be authorized")
	}
	if regResp.AuthURL == "" {
		t.Fatal("expected an AuthURL")
	}

	return conn, client, nodeKey, path.Base(regResp.AuthURL)
}

// registerNode completes an interactive registration: start, approve, follow up.
func registerNode(t *testing.T, s *Server, hs *httptest.Server, hostname string) (net.Conn, *http.Client, key.NodePrivate) {
	t.Helper()

	conn, client, nodeKey, authID := startRegistration(t, hs, hostname)

	if err := s.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	regResp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Followup: s.authURL(authID),
	}))
	if !regResp.MachineAuthorized {
		t.Fatalf("registration not authorized: %+v", regResp)
	}

	return conn, client, nodeKey
}

// openMapSession opens a streaming map session and returns the live response.
func openMapSession(t *testing.T, client *http.Client, nodeKey key.NodePublic) *http.Response {
	t.Helper()

	body, err := json.Marshal(tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
		Stream:  true,
	})
	if err != nil {
		t.Fatalf("marshalling map request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://xunara.test/machine/map", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building map request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("opening map session: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("map session status = %d, want 200", resp.StatusCode)
	}
	return resp
}

// readMapResponse reads one length-prefixed MapResponse from a stream.
func readMapResponse(t *testing.T, r io.Reader) *tailcfg.MapResponse {
	t.Helper()

	var header [reservedResponseHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatalf("reading map response header: %v", err)
	}

	size := binary.LittleEndian.Uint32(header[:])
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("reading map response body: %v", err)
	}

	var msg tailcfg.MapResponse
	if err := json.Unmarshal(payload, &msg); err != nil {
		t.Fatalf("decoding map response: %v", err)
	}
	return &msg
}
