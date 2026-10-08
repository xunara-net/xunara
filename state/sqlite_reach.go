package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This file implements [ReachStore] on SQLite. Sessions are the durable record
// the control plane and both agents follow; output chunks are append-only rows
// that die with the session.

// reachColumns is the shared SELECT list.
const reachColumns = `id, sender_node, target_node, state, argv, timeout_ms,
	exit_code, error, created_at, updated_at, expires_at`

// CreateReachSession implements [ReachStore].
func (s *SQLiteStore) CreateReachSession(session *ReachSession, quotas ReachQuotas) error {
	if err := validateReachSession(session); err != nil {
		return err
	}

	ctx := context.Background()
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: creating reach session: %w", err)
	}
	defer tx.Rollback()

	for _, id := range []NodeID{session.Sender, session.Target} {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE id = ?", int64(id)).Scan(&exists); err != nil {
			return fmt.Errorf("state: looking up node %d: %w", id, err)
		}
		if exists == 0 {
			return errUnknownNode(id)
		}
	}

	var active int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM reach_sessions
		WHERE sender_node = ? AND target_node = ?
		  AND state IN (?, ?, ?)`,
		int64(session.Sender), int64(session.Target),
		string(ReachOffered), string(ReachAccepted), string(ReachRunning)).Scan(&active); err != nil {
		return fmt.Errorf("state: counting reach sessions: %w", err)
	}
	if active >= quotas.maxActivePerPair() {
		return ErrReachSessionQuota
	}

	stored := *session
	if stored.ID == "" {
		id, err := NewReachSessionID()
		if err != nil {
			return err
		}
		stored.ID = id
	}
	if stored.State == "" {
		stored.State = ReachOffered
	}
	now := time.Now().UTC()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	if stored.ExpiresAt.IsZero() {
		stored.ExpiresAt = stored.CreatedAt.Add(ReachMaxOfferAge)
	}
	stored.UpdatedAt = stored.CreatedAt

	argv, err := json.Marshal(stored.Argv)
	if err != nil {
		return fmt.Errorf("state: encoding reach argv: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO reach_sessions(`+reachColumns+`)
		VALUES(?, ?, ?, ?, ?, ?, NULL, '', ?, ?, ?)`,
		stored.ID, int64(stored.Sender), int64(stored.Target), string(stored.State), string(argv),
		stored.Timeout.Milliseconds(),
		stored.CreatedAt.Unix(), stored.UpdatedAt.Unix(), stored.ExpiresAt.Unix()); err != nil {
		if isUniqueViolation(err) {
			return ErrReachSessionState
		}
		return fmt.Errorf("state: creating reach session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: creating reach session: %w", err)
	}

	*session = copyReachSession(stored)
	return nil
}

// GetReachSession implements [ReachStore].
func (s *SQLiteStore) GetReachSession(id string) (ReachSession, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+reachColumns+" FROM reach_sessions WHERE id = ?", id)
	session, err := scanReachSession(row)
	if err != nil {
		return ReachSession{}, false
	}
	return session, true
}

// ListReachSessions implements [ReachStore].
func (s *SQLiteStore) ListReachSessions(nodeID NodeID) []ReachSession {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT `+reachColumns+` FROM reach_sessions
		WHERE sender_node = ? OR target_node = ?
		ORDER BY created_at DESC, id ASC`, int64(nodeID), int64(nodeID))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []ReachSession
	for rows.Next() {
		session, err := scanReachSession(rows)
		if err != nil {
			return nil
		}
		out = append(out, session)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// ListAllReachSessions implements [ReachStore]. Newest first.
func (s *SQLiteStore) ListAllReachSessions() []ReachSession {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT `+reachColumns+` FROM reach_sessions
		ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []ReachSession
	for rows.Next() {
		session, err := scanReachSession(rows)
		if err != nil {
			return nil
		}
		out = append(out, session)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// ReachOutputBytes implements [ReachStore].
func (s *SQLiteStore) ReachOutputBytes(id string) (int64, int64, error) {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT stream, COALESCE(SUM(LENGTH(data)), 0) FROM reach_chunks
		WHERE session_id = ? GROUP BY stream`, id)
	if err != nil {
		return 0, 0, fmt.Errorf("state: reading reach output sizes: %w", err)
	}
	defer rows.Close()

	var stdout, stderr int64
	for rows.Next() {
		var (
			stream string
			bytes  int64
		)
		if err := rows.Scan(&stream, &bytes); err != nil {
			return 0, 0, fmt.Errorf("state: reading reach output sizes: %w", err)
		}
		switch stream {
		case ReachStreamStdout:
			stdout = bytes
		case ReachStreamStderr:
			stderr = bytes
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("state: reading reach output sizes: %w", err)
	}
	return stdout, stderr, nil
}

// SetReachSessionState implements [ReachStore].
func (s *SQLiteStore) SetReachSessionState(id string, from, to ReachState, now time.Time) (bool, error) {
	if !from.Valid() || !to.Valid() {
		return false, ErrReachSessionState
	}
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE reach_sessions SET state = ?, updated_at = ?
		WHERE id = ? AND state = ?`,
		string(to), now.UTC().Unix(), id, string(from))
	return reachUpdateResult(res, err, id)
}

// StartReachSession implements [ReachStore].
func (s *SQLiteStore) StartReachSession(id string, expiresAt, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE reach_sessions SET state = ?, updated_at = ?, expires_at = ?
		WHERE id = ? AND state = ?`,
		string(ReachRunning), now.UTC().Unix(), expiresAt.UTC().Unix(), id, string(ReachAccepted))
	return reachUpdateResult(res, err, id)
}

// FinishReachSession implements [ReachStore].
func (s *SQLiteStore) FinishReachSession(id string, exitCode int, errText string, now time.Time) (bool, error) {
	state := ReachFailed
	if exitCode == 0 && errText == "" {
		state = ReachSucceeded
	}
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE reach_sessions SET state = ?, exit_code = ?, error = ?, updated_at = ?
		WHERE id = ? AND state = ?`,
		string(state), exitCode, truncateReachError(errText), now.UTC().Unix(), id, string(ReachRunning))
	return reachUpdateResult(res, err, id)
}

// reachUpdateResult maps an UPDATE result onto the CAS contract: no matching
// row and no error means the session is in the wrong state.
func reachUpdateResult(res sql.Result, err error, id string) (bool, error) {
	if err != nil {
		return false, fmt.Errorf("state: updating reach session %s: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("state: updating reach session %s: %w", id, err)
	}
	return affected > 0, nil
}

// AppendReachChunk implements [ReachStore].
func (s *SQLiteStore) AppendReachChunk(id, stream string, seq int64, data []byte, maxTotal int64, now time.Time) error {
	if err := validateReachChunk(stream, seq, data, maxTotal); err != nil {
		return err
	}

	ctx := context.Background()
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: appending reach chunk: %w", err)
	}
	defer tx.Rollback()

	var state string
	err = tx.QueryRowContext(ctx, "SELECT state FROM reach_sessions WHERE id = ?", id).Scan(&state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrReachSessionNotFound
	case err != nil:
		return fmt.Errorf("state: appending reach chunk: %w", err)
	}
	if ReachState(state) != ReachRunning {
		return ErrReachSessionState
	}

	var total int64
	if err := tx.QueryRowContext(ctx,
		"SELECT COALESCE(SUM(LENGTH(data)), 0) FROM reach_chunks WHERE session_id = ?", id).Scan(&total); err != nil {
		return fmt.Errorf("state: appending reach chunk: %w", err)
	}
	if total+int64(len(data)) > maxTotal {
		return ErrReachOutputLimit
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO reach_chunks(session_id, stream, seq, data, created_at)
		VALUES(?, ?, ?, ?, ?)`,
		id, stream, seq, data, now.UTC().Unix()); err != nil {
		if isUniqueViolation(err) {
			return ErrReachChunkDuplicate
		}
		return fmt.Errorf("state: appending reach chunk: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: appending reach chunk: %w", err)
	}
	return nil
}

// ReachChunks implements [ReachStore].
func (s *SQLiteStore) ReachChunks(id, stream string, after int64, limit int) ([]ReachChunk, error) {
	if !ReachChunkStreamValid(stream) || limit <= 0 || limit > ReachMaxChunksPerRead {
		return nil, ErrReachSessionState
	}

	ctx := context.Background()
	var exists int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reach_sessions WHERE id = ?", id).Scan(&exists); err != nil {
		return nil, fmt.Errorf("state: reading reach chunks: %w", err)
	}
	if exists == 0 {
		return nil, ErrReachSessionNotFound
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT stream, seq, data, created_at FROM reach_chunks
		WHERE session_id = ? AND stream = ? AND seq > ?
		ORDER BY seq LIMIT ?`, id, stream, after, limit)
	if err != nil {
		return nil, fmt.Errorf("state: reading reach chunks: %w", err)
	}
	defer rows.Close()

	var out []ReachChunk
	for rows.Next() {
		var (
			chunk   ReachChunk
			created int64
		)
		if err := rows.Scan(&chunk.Stream, &chunk.Seq, &chunk.Data, &created); err != nil {
			return nil, fmt.Errorf("state: reading reach chunks: %w", err)
		}
		chunk.Data = append([]byte(nil), chunk.Data...)
		chunk.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, chunk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading reach chunks: %w", err)
	}
	return out, nil
}

// ExpireReachSessions implements [ReachStore].
func (s *SQLiteStore) ExpireReachSessions(now time.Time) ([]ReachSession, error) {
	now = now.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: expiring reach sessions: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT `+reachColumns+` FROM reach_sessions
		WHERE state IN (?, ?, ?) AND expires_at <= ?
		ORDER BY created_at, id`,
		string(ReachOffered), string(ReachAccepted), string(ReachRunning), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("state: expiring reach sessions: %w", err)
	}
	var expired []ReachSession
	for rows.Next() {
		session, err := scanReachSession(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		expired = append(expired, session)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("state: expiring reach sessions: %w", err)
	}
	rows.Close()

	ids := make([]any, 0, len(expired))
	for i := range expired {
		expired[i].State = ReachExpired
		expired[i].UpdatedAt = now
		ids = append(ids, expired[i].ID)
	}
	if len(ids) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		if _, err := tx.ExecContext(ctx, `
			UPDATE reach_sessions SET state = ?, updated_at = ?
			WHERE id IN (`+placeholders+`)`,
			append([]any{string(ReachExpired), now.Unix()}, ids...)...); err != nil {
			return nil, fmt.Errorf("state: expiring reach sessions: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: expiring reach sessions: %w", err)
	}
	return expired, nil
}

// DeleteReachSessions implements [ReachStore].
func (s *SQLiteStore) DeleteReachSessions(before time.Time) (int, error) {
	res, err := s.db.ExecContext(context.Background(), `
		DELETE FROM reach_sessions
		WHERE state NOT IN (?, ?, ?) AND updated_at < ?`,
		string(ReachOffered), string(ReachAccepted), string(ReachRunning),
		before.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("state: deleting reach sessions: %w", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("state: deleting reach sessions: %w", err)
	}
	return int(removed), nil
}

// scanReachSession reads one row in reachColumns order.
func scanReachSession(row interface{ Scan(...any) error }) (ReachSession, error) {
	var (
		session   ReachSession
		state     string
		argv      string
		timeoutMS int64
		exitCode  sql.NullInt64
		created   int64
		updated   int64
		expires   int64
	)
	if err := row.Scan(&session.ID, &session.Sender, &session.Target, &state, &argv,
		&timeoutMS, &exitCode, &session.Error, &created, &updated, &expires); err != nil {
		return ReachSession{}, err
	}
	if err := json.Unmarshal([]byte(argv), &session.Argv); err != nil {
		return ReachSession{}, fmt.Errorf("state: decoding reach argv: %w", err)
	}
	session.State = ReachState(state)
	session.Timeout = time.Duration(timeoutMS) * time.Millisecond
	if exitCode.Valid {
		code := int(exitCode.Int64)
		session.ExitCode = &code
	}
	session.CreatedAt = time.Unix(created, 0).UTC()
	session.UpdatedAt = time.Unix(updated, 0).UTC()
	session.ExpiresAt = time.Unix(expires, 0).UTC()
	return session, nil
}
