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
