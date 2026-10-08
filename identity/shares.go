package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tailscale.com/tailcfg"
)

// Xunara Share: this organization's synthetic user IDs for people in other
// organizations (PROJECT_SPEC section 38).
//
// User IDs are allocated per organization, so presenting a foreign user's real
// ID would collide with a local user. Every foreign user is therefore mapped
// to a synthetic ID in this organization's own range, and the netmap's
// user profiles use that ID (never the foreign one).

// ShareUserIDBase is the first synthetic user ID. It sits far above sequential
// local IDs and below the int32 boundary, and never collides with
// [tailcfg.UserID] values this store assigns to real users.
const ShareUserIDBase tailcfg.UserID = 1 << 41

// ShareUserStore maps foreign users to this organization's synthetic IDs.
type ShareUserStore interface {
	// EnsureShareUser returns the synthetic user ID for a foreign user,
	// allocating one on first use. The key is (remote organization, opaque
	// remote key) and identifies the foreign user.
	EnsureShareUser(remoteOrg, remoteKey string) (tailcfg.UserID, error)
	// ShareUser returns the synthetic user ID for a foreign user without
	// allocating.
	ShareUser(remoteOrg, remoteKey string) (tailcfg.UserID, bool)
}

// identityShareMigration creates the share user table (identity schema
// version 11).
const identityShareMigration = `
CREATE TABLE IF NOT EXISTS share_users (
	remote_org TEXT    NOT NULL,
	remote_key TEXT    NOT NULL,
	synthetic  INTEGER NOT NULL UNIQUE,
	PRIMARY KEY (remote_org, remote_key)
);
`

// EnsureShareUser implements [ShareUserStore].
func (s *SQLiteStore) EnsureShareUser(remoteOrg, remoteKey string) (tailcfg.UserID, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("identity: beginning share user allocation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if id, ok, err := shareUserTx(ctx, tx, remoteOrg, remoteKey); err != nil {
		return 0, err
	} else if ok {
		return id, nil
	}

	var next int64
	err = tx.QueryRowContext(ctx,
		`SELECT value FROM counters WHERE name = ?`, counterNextShareUser).Scan(&next)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		next = 0
	case err != nil:
		return 0, fmt.Errorf("identity: reading the share user counter: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO counters (name, value) VALUES (?, ?)
ON CONFLICT(name) DO UPDATE SET value = excluded.value`,
		counterNextShareUser, next+1); err != nil {
		return 0, fmt.Errorf("identity: advancing the share user counter: %w", err)
	}

	id := ShareUserIDBase + tailcfg.UserID(next)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO share_users (remote_org, remote_key, synthetic) VALUES (?, ?, ?)`,
		remoteOrg, remoteKey, int64(id)); err != nil {
		return 0, fmt.Errorf("identity: storing share user: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("identity: committing share user allocation: %w", err)
	}
	return id, nil
}

// ShareUser implements [ShareUserStore].
func (s *SQLiteStore) ShareUser(remoteOrg, remoteKey string) (tailcfg.UserID, bool) {
	id, ok, err := shareUserTx(context.Background(), s.db, remoteOrg, remoteKey)
	if err != nil {
		return 0, false
	}
	return id, ok
}

// counterNextShareUser is the share-user allocator's counter name. It lives in
// the shared counters table so allocation is atomic with the identity store's
// other counters.
const counterNextShareUser = "next_share_user"

// shareUserTx reads one synthetic user ID inside tx.
func shareUserTx(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, remoteOrg, remoteKey string) (tailcfg.UserID, bool, error) {
	var raw int64
	err := tx.QueryRowContext(ctx,
		`SELECT synthetic FROM share_users WHERE remote_org = ? AND remote_key = ?`,
		remoteOrg, remoteKey).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("identity: reading share user: %w", err)
	}
	return tailcfg.UserID(raw), true, nil
}
