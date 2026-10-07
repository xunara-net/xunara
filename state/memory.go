package state

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/types/key"
)

// Default address ranges for the tailnet. These mirror the ranges the official
// Tailscale clients expect for a tailnet's CGNAT space.
var (
	defaultIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	defaultIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// MemoryStore is an in-memory [Store].
//
// It is safe for concurrent use. It provides no durability; a durable backing
// store is a follow-up milestone. Keeping it behind the [Store] interface means
// the Compatibility Core does not change when durability lands.
type MemoryStore struct {
	mu sync.RWMutex

	nextID    NodeID
	nextKeyID uint64

	byID   map[NodeID]Node
	byNode map[key.NodePublic]NodeID
	byStab map[string]NodeID
	byMach map[key.MachinePublic][]NodeID

	preauth map[string]PreAuthKey

	ip4 *ipAllocator
	ip6 *ipAllocator
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nextID:    1,
		nextKeyID: 1,
		byID:      make(map[NodeID]Node),
		preauth:   make(map[string]PreAuthKey),
		byNode:    make(map[key.NodePublic]NodeID),
		byStab:    make(map[string]NodeID),
		byMach:    make(map[key.MachinePublic][]NodeID),
		ip4:       newIPAllocator(defaultIPv4Prefix),
		ip6:       newIPAllocator(defaultIPv6Prefix),
	}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) GetNodeByID(id NodeID) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.byID[id]
	return n, ok
}

func (s *MemoryStore) GetNodeByNodeKey(nk key.NodePublic) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byNode[nk]
	if !ok {
		return Node{}, false
	}
	n, ok := s.byID[id]
	return n, ok
}

func (s *MemoryStore) GetNodesByMachineKey(mk key.MachinePublic) []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byMach[mk]
	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		if n, ok := s.byID[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

func (s *MemoryStore) GetNodeByStableID(id string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nid, ok := s.byStab[id]
	if !ok {
		return Node{}, false
	}
	n, ok := s.byID[nid]
	return n, ok
}

func (s *MemoryStore) ListNodes() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Node, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, n)
	}
	return out
}

func (s *MemoryStore) CreateNode(n *Node) error {
	if n == nil {
		return fmt.Errorf("state: nil node")
	}
	if n.NodeKey.IsZero() {
		return fmt.Errorf("state: node key is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byNode[n.NodeKey]; ok {
		return ErrNodeKeyExists
	}

	n.ID = s.nextID
	s.nextID++

	if n.StableID == "" {
		n.StableID = newStableID()
	}
	if n.Created.IsZero() {
		n.Created = time.Now().UTC()
	}
	if !n.IPv4.IsValid() {
		addr, ok := s.ip4.next()
		if !ok {
			return fmt.Errorf("state: IPv4 space exhausted")
		}
		n.IPv4 = addr
	}
	if !n.IPv6.IsValid() {
		addr, ok := s.ip6.next()
		if !ok {
			return fmt.Errorf("state: IPv6 space exhausted")
		}
		n.IPv6 = addr
	}

	s.byID[n.ID] = *n
	s.byNode[n.NodeKey] = n.ID
	s.byStab[n.StableID] = n.ID
	s.byMach[n.MachineKey] = append(s.byMach[n.MachineKey], n.ID)
	return nil
}

func (s *MemoryStore) UpdateNode(n Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.byID[n.ID]
	if !ok {
		return fmt.Errorf("state: node %d not found", n.ID)
	}
	if old.NodeKey != n.NodeKey {
		delete(s.byNode, old.NodeKey)
		s.byNode[n.NodeKey] = n.ID
	}
	if old.StableID != n.StableID {
		delete(s.byStab, old.StableID)
		s.byStab[n.StableID] = n.ID
	}
	if old.MachineKey != n.MachineKey {
		s.byMach[old.MachineKey] = removeID(s.byMach[old.MachineKey], n.ID)
		s.byMach[n.MachineKey] = append(s.byMach[n.MachineKey], n.ID)
	}
	s.byID[n.ID] = n
	return nil
}

func (s *MemoryStore) DeleteNode(id NodeID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.byID[id]
	if !ok {
		return nil
	}
	delete(s.byID, id)
	delete(s.byNode, n.NodeKey)
	delete(s.byStab, n.StableID)
	s.byMach[n.MachineKey] = removeID(s.byMach[n.MachineKey], id)
	return nil
}

func removeID(ids []NodeID, id NodeID) []NodeID {
	out := ids[:0]
	for _, v := range ids {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// newStableID returns a random stable node ID.
func newStableID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on supported platforms; fall back to a
		// deterministic-ish value rather than panicking.
		return "n00000000"
	}
	return "n" + hex.EncodeToString(b[:])
}

// ipAllocator hands out sequential addresses from a prefix.
type ipAllocator struct {
	prefix netip.Prefix
	last   netip.Addr
}

func newIPAllocator(p netip.Prefix) *ipAllocator {
	masked := p.Masked()
	return &ipAllocator{prefix: masked, last: masked.Addr()}
}

func (a *ipAllocator) next() (netip.Addr, bool) {
	next := a.last.Next()
	if !next.IsValid() || !a.prefix.Contains(next) {
		return netip.Addr{}, false
	}
	a.last = next
	return next, true
}
