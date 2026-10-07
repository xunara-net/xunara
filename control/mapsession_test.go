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
	self := resp.Node
	changed := sess.diff(resp, peers)
	if changed {
		sess.commit(resp, self, peers)
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
		if resp.Node == nil {
			t.Error("a changed self node must be included")
		}
		if resp.Peers != nil || resp.PeersChanged != nil || resp.PeersChangedPatch != nil || resp.PeersRemoved != nil {
			t.Errorf("self-only update carried peer fields: %+v", resp)
		}
		if resp.Seq != 2 {
			t.Errorf("Seq = %d, want 2", resp.Seq)
		}
		self = renamed
	})

	t.Run("endpoint change is patched", func(t *testing.T) {
		updated := sessionNode(2, "one")
		updated.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}

		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{updated, second}) {
			t.Fatal("diff missed a peer change")
		}
		if len(resp.PeersChangedPatch) != 1 || resp.PeersChangedPatch[0].NodeID != 2 {
			t.Errorf("PeersChangedPatch = %v, want just node 2", resp.PeersChangedPatch)
		}
		if !slicesEqualAddrPorts(resp.PeersChangedPatch[0].Endpoints, updated.Endpoints) {
			t.Errorf("patch endpoints = %v, want %v", resp.PeersChangedPatch[0].Endpoints, updated.Endpoints)
		}
		if resp.Peers != nil || resp.PeersChanged != nil || resp.PeersRemoved != nil {
			t.Errorf("delta frame carried Peers=%v PeersChanged=%v PeersRemoved=%v", resp.Peers, resp.PeersChanged, resp.PeersRemoved)
		}
		if resp.Node != nil {
			t.Error("an unchanged self node must be omitted from a delta frame")
		}
		first = updated
	})

	t.Run("structural change is sent in full", func(t *testing.T) {
		renamed := sessionNode(2, "renamed")
		renamed.Endpoints = first.Endpoints

		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{renamed, second}) {
			t.Fatal("diff missed a structural peer change")
		}
		if len(resp.PeersChanged) != 1 || resp.PeersChanged[0].ID != 2 {
			t.Errorf("PeersChanged = %v, want the full node 2", resp.PeersChanged)
		}
		if resp.PeersChangedPatch != nil {
			t.Errorf("PeersChangedPatch = %v, want none for a structural change", resp.PeersChangedPatch)
		}
		first = renamed
	})

	t.Run("new peer is sent in full", func(t *testing.T) {
		added := sessionNode(4, "four")
		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{first, second, added}) {
			t.Fatal("diff missed a new peer")
		}
		if len(resp.PeersChanged) != 1 || resp.PeersChanged[0].ID != 4 {
			t.Errorf("PeersChanged = %v, want the new node 4 in full", resp.PeersChanged)
		}
		if resp.Peers != nil || resp.PeersRemoved != nil || resp.PeersChangedPatch != nil {
			t.Errorf("unexpected fields: Peers=%v PeersRemoved=%v PeersChangedPatch=%v",
				resp.Peers, resp.PeersRemoved, resp.PeersChangedPatch)
		}
	})

	t.Run("several peers change at once", func(t *testing.T) {
		a := sessionNode(2, "renamed")
		a.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")}
		b := sessionNode(3, "two")
		b.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.8:41641")}

		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{a, b, sessionNode(4, "four")}) {
			t.Fatal("diff missed peer changes")
		}
		if len(resp.PeersChangedPatch) != 2 {
			t.Errorf("PeersChangedPatch = %d entries, want 2", len(resp.PeersChangedPatch))
		}
		if resp.Peers != nil || resp.PeersChanged != nil {
			t.Errorf("a patchable delta must not carry Peers=%v PeersChanged=%v", resp.Peers, resp.PeersChanged)
		}
		first, second = a, b
	})

	t.Run("peer removal", func(t *testing.T) {
		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{first, sessionNode(4, "four")}) {
			t.Fatal("diff missed a removal")
		}
		if len(resp.PeersRemoved) != 1 || resp.PeersRemoved[0] != 3 {
			t.Errorf("PeersRemoved = %v, want [3]", resp.PeersRemoved)
		}
		if resp.Peers != nil {
			t.Errorf("Peers = %v, want nil alongside PeersRemoved", resp.Peers)
		}
		second = nil
	})

	t.Run("empty tailnet removes the last peer", func(t *testing.T) {
		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, nil) {
			t.Fatal("diff missed the removal of the last peer")
		}
		if len(resp.PeersRemoved) != 2 {
			t.Errorf("PeersRemoved = %v, want the two remaining peers", resp.PeersRemoved)
		}
		if resp.Peers != nil {
			t.Errorf("Peers = %v, want nil (an empty list would read as no change)", resp.Peers)
		}
	})

	t.Run("all-new peer set uses the full list", func(t *testing.T) {
		a := sessionNode(8, "eight")
		b := sessionNode(9, "nine")
		resp := &tailcfg.MapResponse{Node: self}
		if !applyFrame(sess, resp, []*tailcfg.Node{a, b}) {
			t.Fatal("diff missed a completely new peer set")
		}
		if len(resp.Peers) != 2 || resp.Peers[0] != a || resp.Peers[1] != b {
			t.Errorf("Peers = %v, want the two new nodes", resp.Peers)
		}
		if resp.PeersChanged != nil || resp.PeersChangedPatch != nil || resp.PeersRemoved != nil {
			t.Errorf("a full list must not carry delta fields: %+v", resp)
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

func TestMapSessionClientVersionSync(t *testing.T) {
	sess, err := newMapSession()
	if err != nil {
		t.Fatalf("newMapSession: %v", err)
	}

	advisory := &tailcfg.ClientVersion{LatestVersion: "1.88.3", Notify: true}
	sess.initial(&tailcfg.MapResponse{Node: sessionNode(1, "self"), ClientVersion: advisory})

	// Repeating the same advisory on later frames would force a client-side
	// rebuild every time, so it is cleared.
	resp := &tailcfg.MapResponse{ClientVersion: &tailcfg.ClientVersion{LatestVersion: "1.88.3", Notify: true}}
	if sess.syncClientVersion(resp) {
		t.Error("an unchanged advisory was reported as changed")
	}
	if resp.ClientVersion != nil {
		t.Error("an unchanged advisory must be cleared from the frame")
	}

	// The client updated: the advisory changes and is sent exactly once.
	latest := &tailcfg.ClientVersion{RunningLatest: true}
	resp = &tailcfg.MapResponse{ClientVersion: latest}
	if !sess.syncClientVersion(resp) {
		t.Fatal("a changed advisory was not reported")
	}
	if resp.ClientVersion != latest {
		t.Error("syncClientVersion did not keep the changed advisory on the frame")
	}

	resp = &tailcfg.MapResponse{ClientVersion: &tailcfg.ClientVersion{RunningLatest: true}}
	if sess.syncClientVersion(resp) || resp.ClientVersion != nil {
		t.Error("a repeated advisory must be cleared")
	}

	// There is no wire form for withdrawing an advisory; that must not be
	// reported as a change (and must not panic).
	resp = &tailcfg.MapResponse{}
	if sess.syncClientVersion(resp) || resp.ClientVersion != nil {
		t.Error("withdrawing an advisory is not expressible and must be a no-op")
	}
}

// slicesEqualAddrPorts is a local equality helper so the test does not have to
// import slices just for one assertion.
func slicesEqualAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
