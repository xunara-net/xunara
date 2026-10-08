package identity

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

// SetLocalCredential implements [LocalCredentialStore].
func (s *SQLiteStore) SetLocalCredential(c *LocalCredential) error {
	if c == nil || c.UserID == 0 {
		return fmt.Errorf("identity: local credential needs a user")
	}
	if len(c.PasswordHash) == 0 {
		return fmt.Errorf("identity: local credential needs a password hash")
	}

	now := time.Now().UTC()
	created := c.CreatedAt
	if created.IsZero() {
		created = now
	}

	// The upsert keeps the original creation time on a password change: the
	// audit trail cares when the account got its first password, and
	// updated_at records the change.
	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO local_credentials (user_id, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			password_hash = excluded.password_hash,
			updated_at    = excluded.updated_at`,
		int64(c.UserID), c.PasswordHash, created.UnixNano(), now.UnixNano()); err != nil {
		return fmt.Errorf("identity: storing local credential: %w", err)
	}
	return nil
}

// GetLocalCredential implements [LocalCredentialStore].
func (s *SQLiteStore) GetLocalCredential(userID tailcfg.UserID) (LocalCredential, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT user_id, password_hash, created_at, updated_at FROM local_credentials WHERE user_id = ?",
		int64(userID))

	var (
		id        int64
		hash      []byte
		createdAt int64
		updatedAt int64
	)
	if err := row.Scan(&id, &hash, &createdAt, &updatedAt); err != nil {
		return LocalCredential{}, false
	}
	return LocalCredential{
		UserID:       tailcfg.UserID(id),
		PasswordHash: hash,
		CreatedAt:    time.Unix(0, createdAt).UTC(),
		UpdatedAt:    time.Unix(0, updatedAt).UTC(),
	}, true
}

// DeleteLocalCredential implements [LocalCredentialStore].
func (s *SQLiteStore) DeleteLocalCredential(userID tailcfg.UserID) error {
	if _, err := s.db.ExecContext(context.Background(),
		"DELETE FROM local_credentials WHERE user_id = ?", int64(userID)); err != nil {
		return fmt.Errorf("identity: deleting local credential: %w", err)
	}
	return nil
}

// CountLocalCredentials implements [LocalCredentialStore].
func (s *SQLiteStore) CountLocalCredentials() int {
	var count int
	if err := s.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM local_credentials").Scan(&count); err != nil {
		return 0
	}
	return count
}
