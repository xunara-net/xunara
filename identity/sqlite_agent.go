package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateAgentToken implements [AgentTokenStore].
func (s *SQLiteStore) CreateAgentToken(opts NewAgentTokenOptions) (AgentToken, string, error) {
	if opts.NodeID == 0 {
		return AgentToken{}, "", fmt.Errorf("identity: agent token needs a node ID")
	}
	if opts.MachineKey == "" || opts.NodeKey == "" {
		return AgentToken{}, "", fmt.Errorf("identity: agent token needs the machine and node keys")
	}

	id, err := newID("xunara_agenttoken_")
	if err != nil {
		return AgentToken{}, "", err
	}
	token, err := newSecret()
	if err != nil {
		return AgentToken{}, "", err
	}
	token = AgentTokenPrefix + token

	now := time.Now().UTC()
	t := AgentToken{
		ID:         id,
		NodeID:     opts.NodeID,
		MachineKey: opts.MachineKey,
		NodeKey:    opts.NodeKey,
		CreatedAt:  now,
	}
	if opts.TTL > 0 {
		t.ExpiresAt = now.Add(opts.TTL)
	}

	if _, err := s.db.ExecContext(context.Background(), `
		INSERT INTO agent_tokens
			(id, node_id, machine_key, node_key, token_hash, created_at, expires_at, last_used_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
		t.ID, t.NodeID, t.MachineKey, t.NodeKey, HashSecret(token),
		t.CreatedAt.UnixNano(), timeToNanos(t.ExpiresAt)); err != nil {
		return AgentToken{}, "", fmt.Errorf("identity: creating agent token: %w", err)
	}
	return t, token, nil
}

// GetAgentTokenByToken implements [AgentTokenStore].
func (s *SQLiteStore) GetAgentTokenByToken(token string) (AgentToken, error) {
	if token == "" {
		return AgentToken{}, ErrAgentTokenNotFound
	}

	row := s.db.QueryRowContext(context.Background(), `
		SELECT id, node_id, machine_key, node_key, created_at, expires_at, last_used_at, revoked_at
		FROM agent_tokens WHERE token_hash = ?`, HashSecret(token))

	t, err := scanAgentToken(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentToken{}, ErrAgentTokenNotFound
		}
		return AgentToken{}, err
	}
	if !t.Live(time.Now().UTC()) {
		return AgentToken{}, ErrAgentTokenNotFound
	}
	return t, nil
}

// TouchAgentToken implements [AgentTokenStore].
func (s *SQLiteStore) TouchAgentToken(id string, now time.Time) error {
	if _, err := s.db.ExecContext(context.Background(),
		"UPDATE agent_tokens SET last_used_at = ? WHERE id = ?",
		now.UTC().UnixNano(), id); err != nil {
		return fmt.Errorf("identity: touching agent token: %w", err)
	}
	return nil
}

// RevokeAgentTokensForNode implements [AgentTokenStore].
func (s *SQLiteStore) RevokeAgentTokensForNode(nodeID int64) error {
	if _, err := s.db.ExecContext(context.Background(),
		"UPDATE agent_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at = 0",
		time.Now().UTC().UnixNano(), nodeID); err != nil {
		return fmt.Errorf("identity: revoking agent tokens: %w", err)
	}
	return nil
}

// ListAgentTokensForNode implements [AgentTokenStore].
func (s *SQLiteStore) ListAgentTokensForNode(nodeID int64) []AgentToken {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT id, node_id, machine_key, node_key, created_at, expires_at, last_used_at, revoked_at
		FROM agent_tokens WHERE node_id = ? ORDER BY created_at DESC`, nodeID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []AgentToken
	for rows.Next() {
		t, err := scanAgentToken(rows.Scan)
		if err != nil {
			return nil
		}
		out = append(out, t)
	}
	return out
}

// ListAgentTokens implements [AgentTokenStore].
func (s *SQLiteStore) ListAgentTokens(limit int) []AgentToken {
	query := `
		SELECT id, node_id, machine_key, node_key, created_at, expires_at, last_used_at, revoked_at
		FROM agent_tokens ORDER BY created_at DESC, id DESC`
	args := []any{}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []AgentToken
	for rows.Next() {
		t, err := scanAgentToken(rows.Scan)
		if err != nil {
			return nil
		}
		out = append(out, t)
	}
	return out
}

// RevokeAgentToken implements [AgentTokenStore].
func (s *SQLiteStore) RevokeAgentToken(id string, now time.Time) error {
	if id == "" {
		return nil
	}
	if _, err := s.db.ExecContext(context.Background(),
		"UPDATE agent_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0",
		now.UTC().UnixNano(), id); err != nil {
		return fmt.Errorf("identity: revoking agent token: %w", err)
	}
	return nil
}

// scanAgentToken reads one row in the canonical column order.
func scanAgentToken(scan func(...any) error) (AgentToken, error) {
	var (
		t                                   AgentToken
		created, expires, lastUsed, revoked int64
	)
	if err := scan(&t.ID, &t.NodeID, &t.MachineKey, &t.NodeKey,
		&created, &expires, &lastUsed, &revoked); err != nil {
		return AgentToken{}, err
	}
	t.CreatedAt = time.Unix(0, created).UTC()
	t.ExpiresAt = nanosToTime(expires)
	t.LastUsedAt = nanosToTime(lastUsed)
	t.RevokedAt = nanosToTime(revoked)
	return t, nil
}

// timeToNanos encodes an optional time as the package's zero sentinel (0).
func timeToNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// nanosToTime decodes the zero sentinel back to a zero time.
func nanosToTime(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}
