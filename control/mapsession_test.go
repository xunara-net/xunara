package control

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func sessionNode(id tailcfg.NodeID, hostname string) *tailcfg.Node {
	return &tailcfg.Node{ID: id, StableID: tailcfg.StableNodeID(hostname), Name: hostname + "."}
}

// applyFrame mirrors the server's streaming loop: diff against the session,
// then commit the frame so the session remembers what the client now has.
func applyFrame(sess *mapSession, resp *tailcfg.MapResponse, peers []*tailcfg.Node) bool {
	changed := sess.diff(resp, peers)
	if changed {
		sess.commit(resp, peers)
	}
	return changed
}

func TestMapSessionInitialFrame(t *testing.T) {
	sess, err := newMapSession()
	if err != nil {
		t.Fatalf("newMapSession: %v", err)
	}
	if sess.handle == "" {
		t.Fatal("expected a non-empty session handle")
	}

	resp := &tailcfg.MapResponse{Node: sessionNode(1, "self"), Peers: []*tailcfg.Node{sessionNode(2, "peer")}}
	sess.initial(resp)

	if resp.MapSessionHandle != sess.handle {
		t.Errorf("handle = %q, want %q", resp.MapSessionHandle, sess.handle)
	}
	if resp.Seq != 1 {
		t.Errorf("Seq = %d, want 1", resp.Seq)
	}
}

func TestMapSessionDelta(t *testing.T) {
	sess, err := newMapSession()
	if err != nil {
		t.Fatalf("newMapSession: %v", err)
	}

	self := sessionNode(1, "self")
	first := sessionNode(2, "one")
	second := sessionNode(3, "two")

	initial := &tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{first, second}}
	sess.initial(initial)

	t.Run("unchanged sends nothing", func(t *testing.T) {
		resp := &tailcfg.MapResponse{Node: self}
		if applyFrame(sess, resp, []*tailcfg.Node{first, second}) {
			t.Error("diff reported a change for an identical netmap")
		}
	})

	t.Run("self-only update", func(t *testing.T) {
		renamed := sessionNode(1, "renamed")
		resp := &tailcfg.MapResponse{Node: renamed}
		if !applyFrame(sess, resp, []*tailcfg.Node{first, second}) {
			t.Fatal("diff missed a self change")
		}
		if resp.Peers != nil || resp.PeersChanged != nil || resp.PeersRemoved != nil {
			t.Errorf("self-only update carried peer fields: %+v", resp)
		}
		if resp.Seq != 2 {
			t.Errorf("Seq = %d, want 2", resp.Seq)
		}
	})

	t.Run("one peer changed", func(t *testing.T) {
		updated := sessionNode(2, "one")
		updated.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}

		resp := &tailcfg.MapResponse{Node: sessionNode(1, "renamed"), Peers: []*tailcfg.Node{updated, second}}
		if !applyFrame(sess, resp, []*tailcfg.Node{updated, second}) {
			t.Fatal("diff missed a peer change")
		}
		if len(resp.PeersChanged) != 1 || resp.PeersChanged[0].ID != 2 {
			t.Errorf("PeersChanged = %v, want just node 2", resp.PeersChanged)
		}
		if resp.Peers != nil || resp.PeersRemoved != nil {
			t.Errorf("delta frame carried Peers=%v PeersRemoved=%v", resp.Peers, resp.PeersRemoved)
		}
	})

	t.Run("all peers changed uses the full list", func(t *testing.T) {
		a := sessionNode(2, "a")
		b := sessionNode(3, "b")
		resp := &tailcfg.MapResponse{Node: sessionNode(1, "renamed")}
		if !applyFrame(sess, resp, []*tailcfg.Node{a, b}) {
			t.Fatal("diff missed a full relist")
		}
		if len(resp.Peers) != 2 {
			t.Errorf("Peers = %v, want the full list", resp.Peers)
		}
		if resp.PeersChanged != nil || resp.PeersRemoved != nil {
			t.Error("a full relist must not carry delta fields")
		}
	})

	t.Run("peer removal", func(t *testing.T) {
		resp := &tailcfg.MapResponse{Node: sessionNode(1, "renamed")}
		if !applyFrame(sess, resp, []*tailcfg.Node{sessionNode(2, "a")}) {
			t.Fatal("diff missed a removal")
		}
		if len(resp.PeersRemoved) != 1 || resp.PeersRemoved[0] != 3 {
			t.Errorf("PeersRemoved = %v, want [3]", resp.PeersRemoved)
		}
		if resp.Peers != nil {
			t.Errorf("Peers = %v, want nil alongside PeersRemoved", resp.Peers)
		}
	})

	t.Run("empty tailnet removes the last peer", func(t *testing.T) {
		resp := &tailcfg.MapResponse{Node: sessionNode(1, "renamed")}
		if !applyFrame(sess, resp, nil) {
			t.Fatal("diff missed the removal of the last peer")
		}
		if len(resp.PeersRemoved) != 1 || resp.PeersRemoved[0] != 2 {
			t.Errorf("PeersRemoved = %v, want [2]", resp.PeersRemoved)
		}
		if resp.Peers != nil {
			t.Errorf("Peers = %v, want nil (an empty list would read as no change)", resp.Peers)
		}
	})
}

func TestMapSessionDNSSync(t *testing.T) {
	sess, err := newMapSession()
	if err != nil {
		t.Fatalf("newMapSession: %v", err)
	}

	initial := &tailcfg.DNSConfig{Domains: []string{"example.com"}, Proxied: true}
	resp := &tailcfg.MapResponse{Node: sessionNode(1, "self"), DNSConfig: initial}
	sess.initial(resp)

	if sess.syncDNS(&tailcfg.MapResponse{}, initial) {
		t.Error("unchanged DNS configuration was reported as changed")
	}

	grown := &tailcfg.DNSConfig{
		Domains:      []string{"example.com"},
		Proxied:      true,
		ExtraRecords: []tailcfg.DNSRecord{{Name: "_acme-challenge.self.example.com.", Type: "TXT", Value: "v"}},
	}
	out := &tailcfg.MapResponse{}
	if !sess.syncDNS(out, grown) {
		t.Fatal("a new extra record was not reported as a DNS change")
	}
	if out.DNSConfig != grown {
		t.Error("syncDNS did not attach the new configuration")
	}
}
