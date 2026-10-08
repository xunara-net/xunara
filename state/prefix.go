package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
)

// Tenant network ranges (PROJECT_SPEC section 54).
//
// A deployment that sells plans gives every tenant its own tailnet address
// range, so the addresses a node may be allocated come from configuration
// rather than from the built-in default. This file holds that half of the
// feature; the commercial half (which tenant holds which range, and whether
// its plan allows a custom one) lives in the platform's PlanRegistry.
//
// The ranges are process-local on purpose: the registry is the durable source
// of truth and the router applies a tenant's range when it starts the
// tenant's control plane. Nothing here is written to the node database, so a
// downgrade or a deleted registry row cannot leave a tailnet unable to start.
//
// Changing a range never re-addresses a node: devices keep the addresses they
// registered with (a live tailnet must not be renumbered under its users), and
// new devices are allocated from the new range. Because ranges may overlap
// across a change, allocation skips addresses that are in use.

// SetAddressPrefixes replaces the ranges new nodes are allocated from. An
// invalid prefix leaves that address family unchanged. Existing nodes keep
// their addresses.
func (s *SQLiteStore) SetAddressPrefixes(v4, v6 netip.Prefix) error {
	if !v4.IsValid() && !v6.IsValid() {
		return errors.New("state: at least one address prefix is required")
	}
	if v4.IsValid() {
		if err := validateAddressPrefix(v4, "IPv4"); err != nil {
			return err
		}
	}
	if v6.IsValid() {
		if err := validateAddressPrefix(v6, "IPv6"); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	if v4.IsValid() && v4 != s.ipv4Prefix {
		s.ipv4Prefix = v4
		changed = true
	}
	if v6.IsValid() && v6 != s.ipv6Prefix {
		s.ipv6Prefix = v6
		changed = true
	}
	if !changed {
		return nil
	}
	// Allocation restarts at the beginning of each range: the offsets that
	// were handed out under the previous range are meaningless now, and
	// starting over is what lets a tenant move to a smaller range without
	// hitting a stale counter. Addresses already in use are skipped by the
	// allocator itself. The first counter value is 1, so the first address
	// handed out is the first host address of the range (never its base).
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: starting prefix update: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	for _, counter := range []string{counterNextIPv4Offset, counterNextIPv6Offset} {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO counters (name, value) VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET value = 1",
			counter); err != nil {
			return fmt.Errorf("state: resetting address allocation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: committing prefix update: %w", err)
	}
	return nil
}

// AddressPrefixes returns the ranges new nodes are allocated from.
func (s *SQLiteStore) AddressPrefixes() (netip.Prefix, netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv4Prefix, s.ipv6Prefix
}

// SetAddressPrefixes replaces the ranges new nodes are allocated from. An
// invalid prefix leaves that address family unchanged.
func (s *MemoryStore) SetAddressPrefixes(v4, v6 netip.Prefix) error {
	if !v4.IsValid() && !v6.IsValid() {
		return errors.New("state: at least one address prefix is required")
	}
	if v4.IsValid() {
		if err := validateAddressPrefix(v4, "IPv4"); err != nil {
			return err
		}
	}
	if v6.IsValid() {
		if err := validateAddressPrefix(v6, "IPv6"); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if v4.IsValid() {
		s.ip4 = newIPAllocator(v4)
		s.ip4.skip = s.addrInUseLocked
	}
	if v6.IsValid() {
		s.ip6 = newIPAllocator(v6)
		s.ip6.skip = s.addrInUseLocked
	}
	return nil
}

// AddressPrefixes returns the ranges new nodes are allocated from.
func (s *MemoryStore) AddressPrefixes() (netip.Prefix, netip.Prefix) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ip4.prefix, s.ip6.prefix
}

// validateAddressPrefix rejects a range of the wrong family or a malformed one.
func validateAddressPrefix(p netip.Prefix, family string) error {
	if !p.IsValid() {
		return fmt.Errorf("state: %s prefix is not valid", family)
	}
	if p.Addr().Is6() == (family == "IPv4") {
		return fmt.Errorf("state: %s prefix %s is not a %s range", family, p, family)
	}
	if p.Bits() == 0 {
		return fmt.Errorf("state: %s prefix %s covers every address", family, p)
	}
	return nil
}

// addrInUse reports whether an address is already assigned to a node. It is
// how allocation stays safe when a tenant's range changes: the default range
// and the new range can overlap, and a node that registered under the old one
// must not have its address handed out again.
func (s *MemoryStore) addrInUseLocked(addr netip.Addr) bool {
	for _, n := range s.byID {
		if n.IPv4 == addr || n.IPv6 == addr {
			return true
		}
	}
	return false
}

// nodeHasIPv4 reports whether any node already holds this IPv4 address.
func nodeHasIPv4(ctx context.Context, tx *sql.Tx, addr netip.Addr) (bool, error) {
	return nodeHasAddr(ctx, tx, "ipv4", addr)
}

// nodeHasIPv6 reports whether any node already holds this IPv6 address.
func nodeHasIPv6(ctx context.Context, tx *sql.Tx, addr netip.Addr) (bool, error) {
	return nodeHasAddr(ctx, tx, "ipv6", addr)
}

// nodeHasAddr looks up one address column. column is one of two call-site
// constants, never user input.
func nodeHasAddr(ctx context.Context, tx *sql.Tx, column string, addr netip.Addr) (bool, error) {
	if column != "ipv4" && column != "ipv6" {
		return false, fmt.Errorf("state: %q is not an address column", column)
	}
	var one int
	err := tx.QueryRowContext(ctx,
		"SELECT 1 FROM nodes WHERE "+column+" = ? LIMIT 1", addr.String()).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("state: checking whether %s is in use: %w", addr, err)
	}
	return true, nil
}

// addressAllocationAttempts bounds how many counter values one allocation may
// try before the range is declared exhausted. It only matters after a range
// change left the allocator scanning past addresses that are already in use.
const addressAllocationAttempts = 1 << 16

// nextNodeAddr allocates the next free address of a range.
//
// The counter keeps allocation monotonic across restarts, and the reserved
// share ranges are skipped: a synthetic masquerade address must never equal a
// real node's address (section 38.4). Addresses already in use are skipped
// too, because a node that registered under the tenant's previous range keeps
// its address and must not be handed out twice.
func nextNodeAddr(
	ctx context.Context,
	tx *sql.Tx,
	counter string,
	prefix netip.Prefix,
	family string,
	inUse func(context.Context, *sql.Tx, netip.Addr) (bool, error),
) (netip.Addr, error) {
	for attempt := 0; attempt < addressAllocationAttempts; attempt++ {
		offset, err := nextCounter(ctx, tx, counter, 1)
		if err != nil {
			return netip.Addr{}, err
		}
		if offset < 0 || offset > math.MaxUint32 {
			return netip.Addr{}, addrExhausted(family)
		}
		addr, ok := addrAtOffset(prefix, uint32(offset))
		if !ok {
			return netip.Addr{}, addrExhausted(family)
		}
		if isShareMasqAddr(addr) {
			continue
		}
		taken, err := inUse(ctx, tx, addr)
		if err != nil {
			return netip.Addr{}, err
		}
		if taken {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, addrExhausted(family)
}

// addrExhausted names the address family in an exhaustion error.
func addrExhausted(family string) error {
	return fmt.Errorf("state: %s space exhausted", family)
}
