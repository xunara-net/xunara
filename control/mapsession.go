package control

import (
	"crypto/rand"
	"encoding/hex"
	"slices"

	"tailscale.com/tailcfg"
)

// mapSession tracks what a streaming client has already been told about the
// tailnet, so later frames can be delta-encoded instead of resending every
// peer.
//
// It also owns the session identity: MapSessionHandle (sent once, on the first
// frame) and the monotonic Seq that a client echoes back in
// MapRequest.MapSessionSeq when it reattaches.
type mapSession struct {
	handle string
	seq    int64

	self  *tailcfg.Node
	peers map[tailcfg.NodeID]*tailcfg.Node
}

// newMapSession starts a session with a fresh opaque handle.
//
// Xunara does not resume a previous session's sequence across connections: a
// client that reattaches always receives a fresh handle and a full netmap,
// which tailcfg.MapResponse explicitly allows ("the server may choose to
// ignore the request for any reason and start a new map session").
func newMapSession() (*mapSession, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &mapSession{handle: hex.EncodeToString(b[:])}, nil
}

// initial stamps resp as the first frame of the session: it carries the
// handle, so the client can tell a resumed session from a fresh one.
func (s *mapSession) initial(resp *tailcfg.MapResponse) {
	s.seq = 1
	resp.MapSessionHandle = s.handle
	resp.Seq = s.seq
	s.record(resp.Node, peersOf(resp))
}

// apply turns resp into a delta against what this session already sent, and
// reports whether the frame carries anything new.
//
// Only Peers/PeersChanged/PeersRemoved and the self node are managed here;
// callers fill in any other field first.
func (s *mapSession) apply(resp *tailcfg.MapResponse, peers []*tailcfg.Node) bool {
	changed := make([]*tailcfg.Node, 0, len(peers))
	seen := make(map[tailcfg.NodeID]bool, len(peers))
	for _, p := range peers {
		seen[p.ID] = true
		if old, ok := s.peers[p.ID]; !ok || !old.Equal(p) {
			changed = append(changed, p)
		}
	}

	var removed []tailcfg.NodeID
	for id := range s.peers {
		if !seen[id] {
			removed = append(removed, id)
		}
	}
	slices.Sort(removed)

	selfChanged := s.self == nil || !s.self.Equal(resp.Node)
	if !selfChanged && len(changed) == 0 && len(removed) == 0 {
		return false
	}

	switch {
	case len(removed) == 0 && len(changed) == len(peers):
		// Every peer is new or changed: the full list is both smaller and
		// unambiguous. A non-empty Peers makes clients ignore the delta
		// fields, so it can never carry PeersRemoved alongside.
		resp.Peers = peers
	case len(changed) == 0 && len(removed) == 0:
		// Self-only update: leave the peer fields nil ("unchanged").
	default:
		resp.Peers = nil
		resp.PeersChanged = changed
		resp.PeersRemoved = removed
	}

	s.record(resp.Node, peers)
	s.seq++
	resp.Seq = s.seq
	return true
}

// record remembers the state a frame put the client in.
func (s *mapSession) record(self *tailcfg.Node, peers []*tailcfg.Node) {
	s.self = self
	s.peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(peers))
	for _, p := range peers {
		s.peers[p.ID] = p
	}
}

func peersOf(resp *tailcfg.MapResponse) []*tailcfg.Node {
	if resp.Peers == nil {
		return nil
	}
	return resp.Peers
}
