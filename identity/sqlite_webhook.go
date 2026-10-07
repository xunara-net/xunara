package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// encodeStringList renders a string slice as JSON for storage.
func encodeStringList(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("identity: encoding string list: %w", err)
	}
	return string(raw), nil
}

// decodeStringList parses a stored string list.
func decodeStringList(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("identity: decoding string list: %w", err)
	}
	return out, nil
}

// boolToInt renders a boolean as SQLite's 0/1.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

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

// webhookEndpointColumns is the canonical column order of webhook_endpoints.
const webhookEndpointColumns = "id, url, secret, events, enabled, created_at, updated_at"

// CreateWebhookEndpoint implements [WebhookEndpointStore].
func (s *SQLiteStore) CreateWebhookEndpoint(e *WebhookEndpoint) error {
	if e.ID == "" {
		return errors.New("identity: webhook endpoint needs an id")
	}
	events, err := encodeStringList(e.Events)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	e.CreatedAt = now
	e.UpdatedAt = now

	_, err = s.db.ExecContext(context.Background(), `
		INSERT INTO webhook_endpoints (id, url, secret, events, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.URL, e.Secret, events, boolToInt(e.Enabled),
		now.UnixNano(), now.UnixNano())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrWebhookEndpointExists
		}
		return fmt.Errorf("identity: creating webhook endpoint: %w", err)
	}
	return nil
}

// GetWebhookEndpoint implements [WebhookEndpointStore].
func (s *SQLiteStore) GetWebhookEndpoint(id string) (WebhookEndpoint, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+webhookEndpointColumns+" FROM webhook_endpoints WHERE id = ?", id)
	e, err := scanWebhookEndpoint(row.Scan)
	if err != nil {
		return WebhookEndpoint{}, false
	}
	return e, true
}

// ListWebhookEndpoints implements [WebhookEndpointStore].
func (s *SQLiteStore) ListWebhookEndpoints() []WebhookEndpoint {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+webhookEndpointColumns+" FROM webhook_endpoints ORDER BY created_at, id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []WebhookEndpoint
	for rows.Next() {
		e, err := scanWebhookEndpoint(rows.Scan)
		if err != nil {
			return nil
		}
		out = append(out, e)
	}
	return out
}

// UpdateWebhookEndpoint implements [WebhookEndpointStore].
func (s *SQLiteStore) UpdateWebhookEndpoint(e WebhookEndpoint) error {
	events, err := encodeStringList(e.Events)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE webhook_endpoints
		SET url = ?, secret = ?, events = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		e.URL, e.Secret, events, boolToInt(e.Enabled), now.UnixNano(), e.ID)
	if err != nil {
		return fmt.Errorf("identity: updating webhook endpoint: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: updating webhook endpoint: %w", err)
	}
	if n == 0 {
		return ErrWebhookEndpointNotFound
	}
	return nil
}

// ErrWebhookEndpointNotFound is returned when an endpoint is unknown.
var ErrWebhookEndpointNotFound = errors.New("identity: webhook endpoint not found")

// DeleteWebhookEndpoint implements [WebhookEndpointStore]. The delivery cursor
// goes with it: a re-created endpoint with the same ID starts from the current
// end of the audit log rather than replaying history.
func (s *SQLiteStore) DeleteWebhookEndpoint(id string) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("identity: deleting webhook endpoint: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(context.Background(), "DELETE FROM webhook_endpoints WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("identity: deleting webhook endpoint: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrWebhookEndpointNotFound
	}
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM webhook_cursors WHERE endpoint = ?", id); err != nil {
		return fmt.Errorf("identity: deleting webhook cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identity: deleting webhook endpoint: %w", err)
	}
	return nil
}

// scanWebhookEndpoint reads one row in the canonical column order.
func scanWebhookEndpoint(scan func(...any) error) (WebhookEndpoint, error) {
	var (
		e                 WebhookEndpoint
		events            string
		enabled           int
		created, modified int64
	)
	if err := scan(&e.ID, &e.URL, &e.Secret, &events, &enabled, &created, &modified); err != nil {
		return WebhookEndpoint{}, err
	}
	parsed, err := decodeStringList(events)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	e.Events = parsed
	e.Enabled = enabled != 0
	e.CreatedAt = time.Unix(0, created).UTC()
	e.UpdatedAt = time.Unix(0, modified).UTC()
	return e, nil
}
