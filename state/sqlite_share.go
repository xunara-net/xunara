package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
)

// sqliteShareMigration creates the share namespace tables (schema version 15).
const sqliteShareMigration = `
CREATE TABLE IF NOT EXISTS share_nodes (
	remote_org TEXT    NOT NULL,
	remote_key TEXT    NOT NULL,
	synthetic  INTEGER NOT NULL UNIQUE,
	PRIMARY KEY (remote_org, remote_key)
);

CREATE TABLE IF NOT EXISTS share_addresses (
	remote_org TEXT NOT NULL,
	remote_key TEXT NOT NULL,
	v4         TEXT NOT NULL,
	v6         TEXT NOT NULL,
	PRIMARY KEY (remote_org, remote_key)
);
`

// EnsureShareNode implements [ShareStore].
func (s *SQLiteStore) EnsureShareNode(remoteOrg, remoteKey string) (NodeID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("state: beginning share node allocation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if id, ok, err := shareNodeTx(ctx, tx, remoteOrg, remoteKey); err != nil {
		return 0, err
	} else if ok {
		return id, nil
	}

	index, err := nextCounter(ctx, tx, counterNextShareNode, 0)
	if err != nil {
		return 0, err
	}
	id := ShareNodeIDBase + NodeID(index)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO share_nodes (remote_org, remote_key, synthetic) VALUES (?, ?, ?)`,
		remoteOrg, remoteKey, int64(id)); err != nil {
		return 0, fmt.Errorf("state: storing share node: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("state: committing share node allocation: %w", err)
	}
	return id, nil
}

// ShareNode implements [ShareStore].
func (s *SQLiteStore) ShareNode(remoteOrg, remoteKey string) (NodeID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok, err := shareNodeTx(context.Background(), s.db, remoteOrg, remoteKey)
	if err != nil {
		return 0, false
	}
	return id, ok
}

// shareNodeTx reads one synthetic node ID inside tx.
func shareNodeTx(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, remoteOrg, remoteKey string) (NodeID, bool, error) {
	var raw int64
	err := tx.QueryRowContext(ctx,
		`SELECT synthetic FROM share_nodes WHERE remote_org = ? AND remote_key = ?`,
		remoteOrg, remoteKey).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("state: reading share node: %w", err)
	}
	return NodeID(raw), true, nil
}

// EnsureShareAddress implements [ShareStore].
func (s *SQLiteStore) EnsureShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("state: beginning share address allocation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if v4, v6, ok, err := shareAddressTx(ctx, tx, remoteOrg, remoteKey); err != nil {
		return netip.Addr{}, netip.Addr{}, err
	} else if ok {
		return v4, v6, nil
	}

	index, err := nextCounter(ctx, tx, counterNextShareAddress, 0)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	v4, v6, err := shareAddressAtOffset(uint64(index))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO share_addresses (remote_org, remote_key, v4, v6) VALUES (?, ?, ?, ?)`,
		remoteOrg, remoteKey, v4.String(), v6.String()); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("state: storing share address: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("state: committing share address allocation: %w", err)
	}
	return v4, v6, nil
}

// ShareAddress implements [ShareStore].
func (s *SQLiteStore) ShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v4, v6, ok, err := shareAddressTx(context.Background(), s.db, remoteOrg, remoteKey)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return v4, v6, ok
}

// shareAddressTx reads one share address pair inside tx.
func shareAddressTx(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, remoteOrg, remoteKey string) (netip.Addr, netip.Addr, bool, error) {
	var rawV4, rawV6 string
	err := tx.QueryRowContext(ctx,
		`SELECT v4, v6 FROM share_addresses WHERE remote_org = ? AND remote_key = ?`,
		remoteOrg, remoteKey).Scan(&rawV4, &rawV6)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return netip.Addr{}, netip.Addr{}, false, nil
	case err != nil:
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("state: reading share address: %w", err)
	}
	v4, err := netip.ParseAddr(rawV4)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("state: parsing share IPv4 address: %w", err)
	}
	v6, err := netip.ParseAddr(rawV6)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("state: parsing share IPv6 address: %w", err)
	}
	return v4, v6, true, nil
}
