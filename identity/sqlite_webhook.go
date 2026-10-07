package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ListAuditAfter implements [WebhookCursorStore].
func (s *SQLiteStore) ListAuditAfter(afterID uint64, limit int) []AuditEvent {
	query := "SELECT id, ts, actor, action, target, detail FROM audit_events WHERE id > ? ORDER BY id"
	args := []any{int64(afterID)}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var (
			id     int64
			ts     int64
			actor  string
			action string
			target string
			detail string
		)
		if err := rows.Scan(&id, &ts, &actor, &action, &target, &detail); err != nil {
			return nil
		}
		out = append(out, AuditEvent{
			ID:     uint64(id),
			Time:   time.Unix(0, ts).UTC(),
			Actor:  actor,
			Action: action,
			Target: target,
			Detail: detail,
		})
	}
	return out
}

// GetWebhookCursor implements [WebhookCursorStore].
func (s *SQLiteStore) GetWebhookCursor(endpoint string) uint64 {
	var last int64
	err := s.db.QueryRowContext(context.Background(),
		"SELECT last_event_id FROM webhook_cursors WHERE endpoint = ?", endpoint).Scan(&last)
	if err != nil {
		if err != sql.ErrNoRows {
			// A failed read means "no cursor": redelivering is safe
			// (at-least-once), skipping is not.
		}
		return 0
	}
	if last < 0 {
		return 0
	}
	return uint64(last)
}

// SetWebhookCursor implements [WebhookCursorStore].
func (s *SQLiteStore) SetWebhookCursor(endpoint string, eventID uint64) error {
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO webhook_cursors (endpoint, last_event_id, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(endpoint) DO UPDATE SET
			last_event_id = excluded.last_event_id,
			updated_at    = excluded.updated_at`,
		endpoint, int64(eventID), time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("identity: setting webhook cursor: %w", err)
	}
	return nil
}

// ClaimWebhookEndpoint implements [WebhookCursorStore].
//
// The claim is a lease: an instance that crashes without releasing it blocks
// delivery only until claim_expires_at.
func (s *SQLiteStore) ClaimWebhookEndpoint(endpoint, owner string, now, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE webhook_cursors
		SET claim_owner = ?, claim_expires_at = ?
		WHERE endpoint = ?
		  AND (claim_owner = '' OR claim_owner = ? OR claim_expires_at <= ?)`,
		owner, expiresAt.UTC().UnixNano(), endpoint, owner, now.UTC().UnixNano())
	if err != nil {
		return false, fmt.Errorf("identity: claiming webhook endpoint: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return true, nil
	}

	// No row yet: create it with the claim. INSERT OR IGNORE loses the race
	// against a concurrent claim, which is the correct outcome.
	res, err = s.db.ExecContext(context.Background(), `
		INSERT OR IGNORE INTO webhook_cursors (endpoint, last_event_id, updated_at, claim_owner, claim_expires_at)
		VALUES (?, 0, ?, ?, ?)`,
		endpoint, now.UTC().UnixNano(), owner, expiresAt.UTC().UnixNano())
	if err != nil {
		return false, fmt.Errorf("identity: claiming webhook endpoint: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("identity: claiming webhook endpoint: %w", err)
	}
	return n > 0, nil
}

// RenewWebhookClaim implements [WebhookCursorStore].
func (s *SQLiteStore) RenewWebhookClaim(endpoint, owner string, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE webhook_cursors SET claim_expires_at = ?
		WHERE endpoint = ? AND claim_owner = ?`,
		expiresAt.UTC().UnixNano(), endpoint, owner)
	if err != nil {
		return false, fmt.Errorf("identity: renewing webhook claim: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("identity: renewing webhook claim: %w", err)
	}
	return n > 0, nil
}

// ReleaseWebhookClaim implements [WebhookCursorStore].
func (s *SQLiteStore) ReleaseWebhookClaim(endpoint, owner string) error {
	if _, err := s.db.ExecContext(context.Background(), `
		UPDATE webhook_cursors SET claim_owner = '', claim_expires_at = 0
		WHERE endpoint = ? AND claim_owner = ?`, endpoint, owner); err != nil {
		return fmt.Errorf("identity: releasing webhook claim: %w", err)
	}
	return nil
}

// WebhookRetryState implements [WebhookCursorStore].
func (s *SQLiteStore) WebhookRetryState(endpoint string) (int, time.Time) {
	var attempts, retryAt int64
	err := s.db.QueryRowContext(context.Background(),
		"SELECT attempts, retry_at FROM webhook_cursors WHERE endpoint = ?", endpoint).
		Scan(&attempts, &retryAt)
	if err != nil {
		// A failed read means "no backoff": a delivery that is a little early
		// is safe (at-least-once), a wrongly skipped one is not.
		return 0, time.Time{}
	}
	if attempts < 0 {
		attempts = 0
	}
	return int(attempts), nanosToTime(retryAt)
}

// SetWebhookRetryState implements [WebhookCursorStore].
func (s *SQLiteStore) SetWebhookRetryState(endpoint string, attempts int, retryAt time.Time) error {
	if attempts < 0 {
		attempts = 0
	}
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO webhook_cursors (endpoint, last_event_id, updated_at, attempts, retry_at)
		VALUES (?, 0, ?, ?, ?)
		ON CONFLICT(endpoint) DO UPDATE SET
			attempts  = excluded.attempts,
			retry_at  = excluded.retry_at,
			updated_at = excluded.updated_at`,
		endpoint, time.Now().UTC().UnixNano(), attempts, timeToNanos(retryAt))
	if err != nil {
		return fmt.Errorf("identity: setting webhook retry state: %w", err)
	}
	return nil
}
