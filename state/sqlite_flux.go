package state

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// fluxColumns is the column list every flux query shares, so scanning stays in
// one place.
const fluxColumns = `id, sender_node, recipient_node, name, size, sha256, state,
	recipient_key, reason, created_at, updated_at, expires_at`

// scanFluxTransfer reads one row in [fluxColumns] order.
func scanFluxTransfer(sc rowScanner) (FluxTransfer, error) {
	var (
		t                       FluxTransfer
		sender, recipient, size int64
		created, updated, exp   int64
		state                   string
	)
	if err := sc.Scan(&t.ID, &sender, &recipient, &t.Name, &size, &t.SHA256, &state,
		&t.RecipientKey, &t.Reason, &created, &updated, &exp); err != nil {
		return FluxTransfer{}, err
	}
	t.SenderNode = NodeID(sender)
	t.RecipientNode = NodeID(recipient)
	t.Size = size
	t.State = FluxTransferState(state)
	t.CreatedAt = time.Unix(0, created).UTC()
	t.UpdatedAt = time.Unix(0, updated).UTC()
	t.ExpiresAt = time.Unix(0, exp).UTC()
	return t, nil
}

// CreateFluxTransfer implements [FluxStore].
func (s *SQLiteStore) CreateFluxTransfer(t *FluxTransfer, quotas FluxQuotas) error {
	if t == nil {
		return fmt.Errorf("state: flux transfer is nil")
	}
	if t.SenderNode == 0 || t.RecipientNode == 0 || t.SenderNode == t.RecipientNode {
		return fmt.Errorf("state: flux transfer needs two distinct nodes")
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: creating flux transfer: %w", err)
	}
	defer tx.Rollback()

	if err := checkFluxQuotas(ctx, tx, t, quotas); err != nil {
		return err
	}

	if t.ID == "" {
		id, err := NewFluxTransferID()
		if err != nil {
			return err
		}
		t.ID = id
	}
	now := time.Now().UTC()
	t.State = FluxPending
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.ExpiresAt.IsZero() {
		return fmt.Errorf("state: flux transfer needs an expiry")
	}
	t.ExpiresAt = t.ExpiresAt.UTC()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO flux_transfers (`+fluxColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, int64(t.SenderNode), int64(t.RecipientNode), t.Name, t.Size, t.SHA256,
		string(t.State), t.RecipientKey, t.Reason,
		t.CreatedAt.UnixNano(), t.UpdatedAt.UnixNano(), t.ExpiresAt.UnixNano()); err != nil {
		return fmt.Errorf("state: storing flux transfer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: committing flux transfer: %w", err)
	}
	return nil
}

// checkFluxQuotas enforces [FluxQuotas] inside the creating transaction, so
// two concurrent offers cannot both slip past a limit.
func checkFluxQuotas(ctx context.Context, tx *sql.Tx, t *FluxTransfer, quotas FluxQuotas) error {
	if quotas.MaxActivePerNode > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM flux_transfers
			WHERE (sender_node = ? OR recipient_node = ?)
			  AND state IN ('pending', 'accepted', 'uploaded')`,
			int64(t.SenderNode), int64(t.SenderNode)).Scan(&active); err != nil {
			return fmt.Errorf("state: counting flux transfers: %w", err)
		}
		if active >= quotas.MaxActivePerNode {
			return fmt.Errorf("%w: node has %d active transfers", ErrFluxQuota, active)
		}
	}
	if quotas.MaxActiveTotal > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM flux_transfers
			WHERE state IN ('pending', 'accepted', 'uploaded')`).Scan(&active); err != nil {
			return fmt.Errorf("state: counting flux transfers: %w", err)
		}
		if active >= quotas.MaxActiveTotal {
			return fmt.Errorf("%w: organization has %d active transfers", ErrFluxQuota, active)
		}
	}
	if quotas.MaxStoredBytes > 0 {
		var stored sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT SUM(size) FROM flux_transfers WHERE state = 'uploaded'`).Scan(&stored); err != nil {
			return fmt.Errorf("state: summing flux content: %w", err)
		}
		if stored.Int64+t.Size > quotas.MaxStoredBytes {
			return fmt.Errorf("%w: %d stored bytes", ErrFluxQuota, stored.Int64)
		}
	}
	return nil
}

// GetFluxTransfer implements [FluxStore].
func (s *SQLiteStore) GetFluxTransfer(id string) (FluxTransfer, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+fluxColumns+` FROM flux_transfers WHERE id = ?`, id)
	t, err := scanFluxTransfer(row)
	if err != nil {
		return FluxTransfer{}, false
	}
	return t, true
}

// ListFluxTransfers implements [FluxStore].
func (s *SQLiteStore) ListFluxTransfers(node NodeID) []FluxTransfer {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT `+fluxColumns+` FROM flux_transfers
		WHERE sender_node = ? OR recipient_node = ?
		ORDER BY created_at DESC, id`,
		int64(node), int64(node))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []FluxTransfer
	for rows.Next() {
		t, err := scanFluxTransfer(rows)
		if err != nil {
			return nil
		}
		out = append(out, t)
	}
	return out
}

// transitionFluxTransfer applies one conditional state change in a
// transaction: the row must exist, the acting node must be the expected party,
// and the current state must be one of from. It returns the updated record.
func (s *SQLiteStore) transitionFluxTransfer(action string, id string, actor NodeID,
	role fluxRole, from []FluxTransferState, to FluxTransferState, reason string, key []byte) (FluxTransfer, error) {

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FluxTransfer{}, fmt.Errorf("state: %s flux transfer: %w", action, err)
	}
	defer tx.Rollback()

	current, err := scanFluxTransfer(tx.QueryRowContext(ctx,
		`SELECT `+fluxColumns+` FROM flux_transfers WHERE id = ?`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return FluxTransfer{}, ErrFluxTransferNotFound
		}
		return FluxTransfer{}, fmt.Errorf("state: reading flux transfer: %w", err)
	}

	// The acting node must hold the expected role; a mismatch is reported as
	// "not found" so transfer IDs cannot probe other nodes.
	actingNode := current.RecipientNode
	if role == fluxSenderRole {
		actingNode = current.SenderNode
	}
	if actingNode != actor {
		return FluxTransfer{}, ErrFluxTransferNotFound
	}

	allowed := false
	for _, state := range from {
		if current.State == state {
			allowed = true
			break
		}
	}
	if !allowed {
		return FluxTransfer{}, fmt.Errorf("%w: state is %s", ErrFluxTransferState, current.State)
	}

	now := time.Now().UTC()
	set := "state = ?, updated_at = ?, reason = ?"
	args := []any{string(to), now.UnixNano(), reason}
	if key != nil {
		set += ", recipient_key = ?"
		args = append(args, key)
	}
	args = append(args, id, string(current.State))

	res, err := tx.ExecContext(ctx,
		`UPDATE flux_transfers SET `+set+` WHERE id = ? AND state = ?`, args...)
	if err != nil {
		return FluxTransfer{}, fmt.Errorf("state: %s flux transfer: %w", action, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return FluxTransfer{}, fmt.Errorf("state: %s flux transfer: %w", action, err)
	}
	if affected == 0 {
		// Another instance moved the row between the read and the update.
		return FluxTransfer{}, fmt.Errorf("%w: concurrent change", ErrFluxTransferState)
	}

	updated, err := scanFluxTransfer(tx.QueryRowContext(ctx,
		`SELECT `+fluxColumns+` FROM flux_transfers WHERE id = ?`, id))
	if err != nil {
		return FluxTransfer{}, fmt.Errorf("state: reading flux transfer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return FluxTransfer{}, fmt.Errorf("state: %s flux transfer: %w", action, err)
	}
	return updated, nil
}

// AcceptFluxTransfer implements [FluxStore]; the recipient acts.
func (s *SQLiteStore) AcceptFluxTransfer(id string, recipient NodeID, publicKey []byte) (FluxTransfer, error) {
	return s.transitionFluxTransfer("accepting", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxPending}, FluxAccepted, "", publicKey)
}

// DenyFluxTransfer implements [FluxStore]; the recipient acts.
func (s *SQLiteStore) DenyFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error) {
	return s.transitionFluxTransfer("denying", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxPending}, FluxDenied, reason, nil)
}

// CancelFluxTransfer implements [FluxStore]; the sender acts.
func (s *SQLiteStore) CancelFluxTransfer(id string, sender NodeID) (FluxTransfer, error) {
	return s.transitionFluxTransfer("cancelling", id, sender, fluxSenderRole,
		[]FluxTransferState{FluxPending, FluxAccepted}, FluxCancelled, "", nil)
}

// UploadFluxTransfer implements [FluxStore]; the sender acts.
func (s *SQLiteStore) UploadFluxTransfer(id string, sender NodeID) (FluxTransfer, error) {
	return s.transitionFluxTransfer("uploading", id, sender, fluxSenderRole,
		[]FluxTransferState{FluxAccepted}, FluxUploaded, "", nil)
}

// CompleteFluxTransfer implements [FluxStore]; the recipient acts.
func (s *SQLiteStore) CompleteFluxTransfer(id string, recipient NodeID) (FluxTransfer, error) {
	return s.transitionFluxTransfer("completing", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxUploaded}, FluxCompleted, "", nil)
}

// FailFluxTransfer implements [FluxStore]; the recipient acts.
func (s *SQLiteStore) FailFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error) {
	return s.transitionFluxTransfer("failing", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxAccepted, FluxUploaded}, FluxFailed, reason, nil)
}

// ExpireFluxTransfers implements [FluxStore].
func (s *SQLiteStore) ExpireFluxTransfers(now time.Time) ([]FluxTransfer, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: expiring flux transfers: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT `+fluxColumns+` FROM flux_transfers
		WHERE state IN ('pending', 'accepted', 'uploaded') AND expires_at <= ?`,
		now.UTC().UnixNano())
	if err != nil {
		return nil, fmt.Errorf("state: reading expired flux transfers: %w", err)
	}
	var expired []FluxTransfer
	for rows.Next() {
		t, err := scanFluxTransfer(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("state: scanning expired flux transfer: %w", err)
		}
		expired = append(expired, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading expired flux transfers: %w", err)
	}
	if len(expired) == 0 {
		return nil, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE flux_transfers SET state = 'expired', updated_at = ?
		WHERE state IN ('pending', 'accepted', 'uploaded') AND expires_at <= ?`,
		now.UTC().UnixNano(), now.UTC().UnixNano()); err != nil {
		return nil, fmt.Errorf("state: expiring flux transfers: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: expiring flux transfers: %w", err)
	}
	// The rows were read before the update; return them with the state the
	// update applied.
	for i := range expired {
		expired[i].State = FluxExpired
		expired[i].UpdatedAt = now.UTC()
	}
	return expired, nil
}

// PruneFluxTransfers implements [FluxStore].
func (s *SQLiteStore) PruneFluxTransfers(cutoff time.Time) ([]FluxTransfer, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: pruning flux transfers: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT `+fluxColumns+` FROM flux_transfers
		WHERE state IN ('completed', 'denied', 'failed', 'cancelled', 'expired')
		  AND updated_at < ?`,
		cutoff.UTC().UnixNano())
	if err != nil {
		return nil, fmt.Errorf("state: reading prunable flux transfers: %w", err)
	}
	var pruned []FluxTransfer
	for rows.Next() {
		t, err := scanFluxTransfer(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("state: scanning prunable flux transfer: %w", err)
		}
		pruned = append(pruned, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading prunable flux transfers: %w", err)
	}
	if len(pruned) == 0 {
		return nil, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM flux_transfers
		WHERE state IN ('completed', 'denied', 'failed', 'cancelled', 'expired')
		  AND updated_at < ?`, cutoff.UTC().UnixNano()); err != nil {
		return nil, fmt.Errorf("state: pruning flux transfers: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: pruning flux transfers: %w", err)
	}
	return pruned, nil
}

// FluxStoredBytes implements [FluxStore].
func (s *SQLiteStore) FluxStoredBytes() (int64, error) {
	var stored sql.NullInt64
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT SUM(size) FROM flux_transfers WHERE state = 'uploaded'`).Scan(&stored); err != nil {
		return 0, fmt.Errorf("state: summing flux content: %w", err)
	}
	return stored.Int64, nil
}
