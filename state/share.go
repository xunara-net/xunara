package state

import (
	"fmt"
	"net/netip"
	"sync"
)

// Xunara Share: the per-organization namespace this store uses to present
// nodes shared from another organization (PROJECT_SPEC section 38).
//
// A shared-in node must not reuse the foreign node's numeric ID or addresses:
// two organizations allocate both independently, so exposing them verbatim
// would let one tenant's identifiers collide with (or be mistaken for) the
// other's. Instead each organization allocates its own synthetic node ID and
// its own masquerade addresses for every foreign party it presents, and both
// sides derive the WireGuard-visible addresses from those allocations.

// Share masquerade ranges. They are the last IPv4 /16 and IPv6 /64 of the
// tailnet address space; node address allocation skips them so a synthetic
// address can never collide with a real node's address.
var (
	ShareMasqIPv4Prefix = netip.MustParsePrefix("100.127.0.0/16")
	ShareMasqIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0:ffff::/64")
)

// ShareNodeIDBase is the first synthetic node ID. Synthetic IDs live far above
// the sequential local IDs (and below any int32 truncation point), so a
// synthetic ID can never equal a local one.
const ShareNodeIDBase NodeID = 1 << 40

// ShareStore is the durable namespace for shared-in nodes.
type ShareStore interface {
	// EnsureShareNode returns this store's synthetic node ID for a foreign
	// node, allocating one on first use. The key is (remote organization,
	// opaque remote key) and identifies the foreign node.
	EnsureShareNode(remoteOrg, remoteKey string) (NodeID, error)
	// ShareNode returns the synthetic node ID for a foreign node without
	// allocating.
	ShareNode(remoteOrg, remoteKey string) (NodeID, bool)
	// EnsureShareAddress returns this store's masquerade addresses (IPv4,
	// IPv6) for a foreign party, allocating them on first use. Both addresses
	// come from the reserved share ranges.
	EnsureShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error)
	// ShareAddress returns the masquerade addresses for a foreign party
	// without allocating.
	ShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, bool)
}

// isShareMasqAddr reports whether addr falls inside a reserve share range.
func isShareMasqAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4() {
		return ShareMasqIPv4Prefix.Contains(addr)
	}
	return ShareMasqIPv6Prefix.Contains(addr)
}

// shareAddressAtOffset returns the v4/v6 masquerade address pair for an
// allocation index (starting at 0).
func shareAddressAtOffset(index uint64) (netip.Addr, netip.Addr, error) {
	v4Base := ShareMasqIPv4Prefix.Masked().Addr().As4()
	v4Host := index + 1 // .0 stays unused
	if v4Host > 1<<16-1 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("state: share IPv4 space exhausted")
	}
	v4Base[2] = byte(v4Host >> 8)
	v4Base[3] = byte(v4Host)
	v4 := netip.AddrFrom4(v4Base)

	v6Base := ShareMasqIPv6Prefix.Masked().Addr().As16()
	v6Host := index + 1
	v6Base[8] = byte(v6Host >> 56)
	v6Base[9] = byte(v6Host >> 48)
	v6Base[10] = byte(v6Host >> 40)
	v6Base[11] = byte(v6Host >> 32)
	v6Base[12] = byte(v6Host >> 24)
	v6Base[13] = byte(v6Host >> 16)
	v6Base[14] = byte(v6Host >> 8)
	v6Base[15] = byte(v6Host)
	v6 := netip.AddrFrom16(v6Base)

	return v4, v6, nil
}

// shareKey joins a remote organization and key into one map key.
func shareKey(remoteOrg, remoteKey string) string {
	return remoteOrg + "\x00" + remoteKey
}

// shareAddress is one allocation for a foreign party.
type shareAddress struct {
	v4 netip.Addr
	v6 netip.Addr
}

// memoryShareStore is the in-memory [ShareStore] half of [MemoryStore].
type memoryShareStore struct {
	mu sync.Mutex

	nodes map[string]NodeID
	addrs map[string]shareAddress

	nextNode uint64
	nextAddr uint64
}

func newMemoryShareStore() *memoryShareStore {
	return &memoryShareStore{
		nodes: make(map[string]NodeID),
		addrs: make(map[string]shareAddress),
	}
}

var _ ShareStore = (*memoryShareStore)(nil)

// EnsureShareNode implements [ShareStore].
func (s *memoryShareStore) EnsureShareNode(remoteOrg, remoteKey string) (NodeID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := shareKey(remoteOrg, remoteKey)
	if id, ok := s.nodes[key]; ok {
		return id, nil
	}
	id := ShareNodeIDBase + NodeID(s.nextNode)
	s.nextNode++
	s.nodes[key] = id
	return id, nil
}

// ShareNode implements [ShareStore].
func (s *memoryShareStore) ShareNode(remoteOrg, remoteKey string) (NodeID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.nodes[shareKey(remoteOrg, remoteKey)]
	return id, ok
}

// EnsureShareAddress implements [ShareStore].
func (s *memoryShareStore) EnsureShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := shareKey(remoteOrg, remoteKey)
	if addr, ok := s.addrs[key]; ok {
		return addr.v4, addr.v6, nil
	}
	v4, v6, err := shareAddressAtOffset(s.nextAddr)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	s.nextAddr++
	s.addrs[key] = shareAddress{v4: v4, v6: v6}
	return v4, v6, nil
}

// ShareAddress implements [ShareStore].
func (s *memoryShareStore) ShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr, ok := s.addrs[shareKey(remoteOrg, remoteKey)]
	return addr.v4, addr.v6, ok
}
