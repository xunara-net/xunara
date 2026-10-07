package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/control/mapper"
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

	// dns fingerprints the DNS configuration this session already sent. The
	// netmap update path normally omits DNSConfig (it forces clients into a
	// full rebuild), so it is added back only when it actually changed.
	dns string

	// filter fingerprints the packet filter this session already sent, for the
	// same reason as dns.
	filter string
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

// initial stamps resp as the first frame of the session: it carries the full
// netmap and the handle, so the client can tell a resumed session from a fresh
// one.
func (s *mapSession) initial(resp *tailcfg.MapResponse) {
	s.record(resp.Node, peersOf(resp))
	s.dns = fingerprintDNS(resp.DNSConfig)
	s.filter = fingerprintFilter(filterFromResponse(resp))

	s.seq = 1
	resp.MapSessionHandle = s.handle
	resp.Seq = s.seq
}

// diff rewrites resp's peer fields as a delta against what this session already
// sent, and reports whether the self node or any peer changed.
//
// The caller stamps the frame with [mapSession.commit] once it knows the frame
// carries something, which may also be a DNS change rather than a peer change.
func (s *mapSession) diff(resp *tailcfg.MapResponse, peers []*tailcfg.Node) bool {
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

	switch {
	case len(removed) == 0 && len(changed) == len(peers):
		// Every peer is new or changed: the full list is both smaller and
		// unambiguous. A non-empty Peers makes clients ignore the delta
		// fields, so it can never carry PeersRemoved alongside.
		resp.Peers = peers
		resp.PeersChanged, resp.PeersRemoved = nil, nil
	case len(changed) == 0 && len(removed) == 0:
		// Nothing peer-shaped changed: nil means "unchanged" on the wire.
		resp.Peers, resp.PeersChanged, resp.PeersRemoved = nil, nil, nil
	default:
		resp.Peers = nil
		resp.PeersChanged = changed
		resp.PeersRemoved = removed
	}

	return s.self == nil || !s.self.Equal(resp.Node) || len(changed) > 0 || len(removed) > 0
}

// syncDNS attaches dns to resp when it differs from what this session already
// sent, and reports whether it did.
func (s *mapSession) syncDNS(resp *tailcfg.MapResponse, dns *tailcfg.DNSConfig) bool {
	fp := fingerprintDNS(dns)
	if fp == s.dns {
		return false
	}
	s.dns = fp
	resp.DNSConfig = dns
	return true
}

// syncPacketFilter attaches rules to resp when they differ from what this
// session already sent, and reports whether it did.
func (s *mapSession) syncPacketFilter(resp *tailcfg.MapResponse, rules []tailcfg.FilterRule, capVer tailcfg.CapabilityVersion) bool {
	fp := fingerprintFilter(rules)
	if fp == s.filter {
		return false
	}
	s.filter = fp
	mapper.SetPacketFilters(resp, capVer, rules)
	return true
}

// commit stamps a frame that is about to be written with the session sequence
// number and records the state it puts the client in.
func (s *mapSession) commit(resp *tailcfg.MapResponse, peers []*tailcfg.Node) {
	s.record(resp.Node, peers)
	s.seq++
	resp.Seq = s.seq
}

// fingerprintDNS renders a DNS configuration into a comparable string. An
// empty string means "no configuration".
func fingerprintDNS(dns *tailcfg.DNSConfig) string {
	if dns == nil {
		return ""
	}
	b, err := json.Marshal(dns)
	if err != nil {
		return ""
	}
	return string(b)
}

// fingerprintFilter renders packet filter rules into a comparable string.
func fingerprintFilter(rules []tailcfg.FilterRule) string {
	if len(rules) == 0 {
		return ""
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return ""
	}
	return string(b)
}

// filterFromResponse extracts the rules a response carries, whichever field the
// client's capability version uses.
func filterFromResponse(resp *tailcfg.MapResponse) []tailcfg.FilterRule {
	if rules, ok := resp.PacketFilters["base"]; ok {
		return rules
	}
	return resp.PacketFilter
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
