package control

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

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

// netmapView applies MapResponse frames to in-memory client state the way an
// official Tailscale client does, so tests can assert on the netmap a client
// ends up with rather than on the framing of a single response.
type netmapView struct {
	self  *tailcfg.Node
	peers map[tailcfg.NodeID]*tailcfg.Node
}

func newNetmapView() *netmapView {
	return &netmapView{peers: make(map[tailcfg.NodeID]*tailcfg.Node)}
}

// apply folds one MapResponse into the view, following the documented
// precedence: a non-empty Peers replaces the whole list and makes the delta
// fields meaningless; otherwise PeersChanged adds/updates and PeersRemoved
// deletes; PeersChangedPatch mutates the fields it carries.
func (v *netmapView) apply(msg *tailcfg.MapResponse) {
	if msg.Node != nil {
		v.self = msg.Node
	}
	if msg.Peers != nil {
		v.peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(msg.Peers))
	}
	for _, p := range msg.Peers {
		v.peers[p.ID] = p
	}
	for _, p := range msg.PeersChanged {
		v.peers[p.ID] = p
	}
	for _, pc := range msg.PeersChangedPatch {
		if p, ok := v.peers[pc.NodeID]; ok {
			v.peers[pc.NodeID] = applyPeerChange(p, pc)
		}
	}
	for _, id := range msg.PeersRemoved {
		delete(v.peers, id)
	}
}

// applyPeerChange folds one tailcfg.PeerChange into a stored peer the way an
// official client does: every field the patch carries replaces the stored
// value, fields it leaves unset stay as they were.
func applyPeerChange(p *tailcfg.Node, pc *tailcfg.PeerChange) *tailcfg.Node {
	out := *p
	if pc.DERPRegion != 0 {
		out.HomeDERP = pc.DERPRegion
	}
	if pc.Cap != 0 {
		out.Cap = pc.Cap
	}
	if pc.CapMap != nil {
		out.CapMap = pc.CapMap
	}
	if pc.Endpoints != nil {
		out.Endpoints = pc.Endpoints
	}
	if pc.Key != nil {
		out.Key = *pc.Key
	}
	if pc.KeySignature != nil {
		out.KeySignature = pc.KeySignature
	}
	if pc.DiscoKey != nil {
		out.DiscoKey = *pc.DiscoKey
	}
	if pc.Online != nil {
		online := *pc.Online
		out.Online = &online
	}
	if pc.LastSeen != nil {
		seen := *pc.LastSeen
		out.LastSeen = &seen
	}
	if pc.KeyExpiry != nil {
		out.KeyExpiry = *pc.KeyExpiry
	}
	return &out
}

// peerList returns the peers in the view, sorted by ID as the wire requires.
func (v *netmapView) peerList() []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, len(v.peers))
	for _, p := range v.peers {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *tailcfg.Node) int { return int(a.ID) - int(b.ID) })
	return out
}

// waitForNetmapFrame is waitForNetmap, returning the frame that satisfied cond.
func waitForNetmapFrame(t *testing.T, frames <-chan *tailcfg.MapResponse, view *netmapView, cond func(*netmapView) bool) *tailcfg.MapResponse {
	t.Helper()

	deadline := time.After(15 * time.Second)
	for {
		select {
		case msg, ok := <-frames:
			if !ok {
				t.Fatal("map stream closed while waiting for a netmap update")
			}
			view.apply(msg)
			if cond(view) {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a netmap update (view: %+v)", view)
		}
	}
}

// waitForNetmap consumes frames until cond accepts the accumulated view.
func waitForNetmap(t *testing.T, frames <-chan *tailcfg.MapResponse, view *netmapView, cond func(*netmapView) bool) {
	t.Helper()

	deadline := time.After(15 * time.Second)
	for {
		select {
		case msg, ok := <-frames:
			if !ok {
				t.Fatal("map stream closed while waiting for a netmap update")
			}
			view.apply(msg)
			if cond(view) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a netmap update (view: %+v)", view)
		}
	}
}
