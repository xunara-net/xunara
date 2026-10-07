package control

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/state"
)

// advertisedHostinfo returns Hostinfo that advertises the given routes.
func advertisedHostinfo(hostname string, routes ...netip.Prefix) *tailcfg.Hostinfo {
	return &tailcfg.Hostinfo{Hostname: hostname, RoutableIPs: routes}
}

// mapFrames decodes the length-prefixed MapResponse frames of a streaming
// session in the background. It closes the channel when the stream ends.
func mapFrames(r io.Reader) <-chan *tailcfg.MapResponse {
	out := make(chan *tailcfg.MapResponse)
	go func() {
		defer close(out)
		for {
			var header [reservedResponseHeaderSize]byte
			if _, err := io.ReadFull(r, header[:]); err != nil {
				return
			}
			payload := make([]byte, binary.LittleEndian.Uint32(header[:]))
			if _, err := io.ReadFull(r, payload); err != nil {
				return
			}
			var msg tailcfg.MapResponse
			if err := json.Unmarshal(payload, &msg); err != nil {
				return
			}
			out <- &msg
		}
	}()
	return out
}

// waitForFrame consumes frames until cond accepts one or the deadline expires.
func waitForFrame(t *testing.T, frames <-chan *tailcfg.MapResponse, cond func(*tailcfg.MapResponse) bool) *tailcfg.MapResponse {
	t.Helper()

	deadline := time.After(15 * time.Second)
	var last *tailcfg.MapResponse
	for {
		select {
		case msg, ok := <-frames:
			if !ok {
				t.Fatalf("map stream closed while waiting (last frame: %+v)", last)
			}
			last = msg
			if cond(msg) {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a netmap update (last frame: %+v)", last)
		}
	}
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, p := range prefixes {
		if p == want {
			return true
		}
	}
	return false
}

// TestRoutesRequireApproval drives the route lifecycle through the control API:
// an advertised route is invisible until an administrator approves it, and
// exit routes land in AllowedIPs but never in PrimaryRoutes.
func TestRoutesRequireApproval(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "router")
	defer conn.Close()

	subnet := netip.MustParsePrefix("192.168.7.0/24")

	// The client advertises a subnet route and the IPv4 default route.
	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: advertisedHostinfo("router", subnet, state.ExitRouteV4),
	}), "")

	if containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Fatalf("unapproved route %s is already in AllowedIPs: %v", subnet, msg.Node.AllowedIPs)
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found after map request")
	}
	if got := node.AnnouncedRoutes(); len(got) != 2 {
		t.Fatalf("announced routes = %v, want the two advertised prefixes", got)
	}

	if err := s.Store().SetNodeApprovedRoutes(node.ID, []netip.Prefix{subnet, state.ExitRouteV4}); err != nil {
		t.Fatalf("SetNodeApprovedRoutes: %v", err)
	}

	msg = decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	if !containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Errorf("approved route %s missing from AllowedIPs %v", subnet, msg.Node.AllowedIPs)
	}
	if !containsPrefix(msg.Node.AllowedIPs, state.ExitRouteV4) {
		t.Errorf("approved exit route missing from AllowedIPs %v", msg.Node.AllowedIPs)
	}
	if !containsPrefix(msg.Node.PrimaryRoutes, subnet) {
		t.Errorf("approved subnet route missing from PrimaryRoutes %v", msg.Node.PrimaryRoutes)
	}
	for _, r := range msg.Node.PrimaryRoutes {
		if state.IsExitRoute(r) {
			t.Errorf("exit route %s must not appear in PrimaryRoutes", r)
		}
	}

	// Withdrawing approval takes the route away again.
	if err := s.Store().SetNodeApprovedRoutes(node.ID, nil); err != nil {
		t.Fatalf("clearing routes: %v", err)
	}
	msg = decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Errorf("withdrawn route %s is still in AllowedIPs %v", subnet, msg.Node.AllowedIPs)
	}
}

// TestRouteApprovalPushesToConnectedPeers covers the out-of-band approval path:
// the CLI writes approved routes and bumps the configuration revision; running
// servers notice and push an updated netmap.
func TestRouteApprovalPushesToConnectedPeers(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "node-a")
	defer connA.Close()

	sess := openMapSession(t, clientA, nodeKeyA.Public())
	defer sess.Body.Close()

	frames := mapFrames(sess.Body)

	first := waitForFrame(t, frames, func(*tailcfg.MapResponse) bool { return true })
	if len(first.Peers) != 0 {
		t.Fatalf("peers before node B registered = %d, want 0", len(first.Peers))
	}

	connB, clientB, nodeKeyB := registerNode(t, s, hs, "node-b")
	defer connB.Close()

	subnet := netip.MustParsePrefix("10.99.0.0/16")
	postRaw(t, clientB, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKeyB.Public(),
		Hostinfo: advertisedHostinfo("node-b", subnet),
	})

	second := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool { return len(m.Peers) == 1 })
	if containsPrefix(second.Peers[0].AllowedIPs, subnet) {
		t.Fatalf("unapproved route already visible to peers: %v", second.Peers[0].AllowedIPs)
	}

	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node B not found")
	}
	if err := s.Store().SetNodeApprovedRoutes(nodeB.ID, []netip.Prefix{subnet}); err != nil {
		t.Fatalf("SetNodeApprovedRoutes: %v", err)
	}
	if err := s.Store().BumpConfigRevision(); err != nil {
		t.Fatalf("BumpConfigRevision: %v", err)
	}

	third := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool {
		return len(m.Peers) == 1 && containsPrefix(m.Peers[0].AllowedIPs, subnet)
	})
	if !containsPrefix(third.Peers[0].PrimaryRoutes, subnet) {
		t.Errorf("approved route %s missing from peer PrimaryRoutes %v", subnet, third.Peers[0].PrimaryRoutes)
	}
}
