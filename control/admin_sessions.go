package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Admin console sessions (PROJECT_SPEC section 54).
//
// The platform operator's browser session is deliberately not a tenant session
// and not a shared map: it lives in the platform registry, so it survives a
// restart, is revocable, expires, and works when two instances serve the same
// deployment (AGENTS.md section 9). Its token is a bearer credential, so only
// its SHA-256 is stored, and the tenant console never accepts it: the cookie
// name, the store and the verification path are all distinct.

// AdminSessionTTL bounds a platform console session.
const AdminSessionTTL = 12 * time.Hour

// ErrAdminSessionNotFound is returned for an unknown, expired or revoked
// admin session.
var ErrAdminSessionNotFound = errors.New("control: no such admin session")

// AdminSession is one platform console session.
type AdminSession struct {
	ID         string
	CSRF       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RevokedAt  time.Time
}

// CreateAdminSession opens a session and returns its token. Only the token's
// hash is stored, so the token is returned exactly once.
func (g *PlanRegistry) CreateAdminSession(ttl time.Duration) (AdminSession, string, error) {
	if ttl <= 0 {
		ttl = AdminSessionTTL
	}
	token, err := newAdminToken()
	if err != nil {
		return AdminSession{}, "", err
	}
	csrf, err := newAdminToken()
	if err != nil {
		return AdminSession{}, "", err
	}
	id, err := newAdminToken()
	if err != nil {
		return AdminSession{}, "", err
	}

	now := time.Now().UTC()
	session := AdminSession{ID: id, CSRF: csrf, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(ttl)}
	_, err = g.db.ExecContext(context.Background(), `
		INSERT INTO admin_sessions (id, token_hash, csrf_token, created_at, expires_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID, adminTokenHash(token), session.CSRF,
		now.UnixNano(), session.ExpiresAt.UnixNano(), now.UnixNano())
	if err != nil {
		return AdminSession{}, "", fmt.Errorf("control: creating admin session: %w", err)
	}
	return session, token, nil
}

// AdminSession resolves a token to a live session, refreshing its last-seen
// time. Expired and revoked sessions are not found.
func (g *PlanRegistry) AdminSession(token string) (AdminSession, error) {
	if token == "" {
		return AdminSession{}, ErrAdminSessionNotFound
	}
	ctx := context.Background()
	row := g.db.QueryRowContext(ctx, `
		SELECT id, csrf_token, created_at, expires_at, last_seen_at, revoked_at
		FROM admin_sessions WHERE token_hash = ?`, adminTokenHash(token))

	var (
		session   AdminSession
		created   int64
		expires   int64
		lastSeen  int64
		revokedAt sql.NullInt64
	)
	if err := row.Scan(&session.ID, &session.CSRF, &created, &expires, &lastSeen, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AdminSession{}, ErrAdminSessionNotFound
		}
		return AdminSession{}, fmt.Errorf("control: reading admin session: %w", err)
	}
	session.CreatedAt = time.Unix(0, created).UTC()
	session.ExpiresAt = time.Unix(0, expires).UTC()
	session.LastSeenAt = time.Unix(0, lastSeen).UTC()
	if revokedAt.Valid {
		session.RevokedAt = time.Unix(0, revokedAt.Int64).UTC()
	}
	if !session.RevokedAt.IsZero() || !time.Now().UTC().Before(session.ExpiresAt) {
		return AdminSession{}, ErrAdminSessionNotFound
	}
	if _, err := g.db.ExecContext(ctx,
		"UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?",
		time.Now().UTC().UnixNano(), session.ID); err != nil {
		return AdminSession{}, fmt.Errorf("control: touching admin session: %w", err)
	}
	return session, nil
}

// RevokeAdminSession revokes one session. Revoking an unknown session is not
// an error: signing out twice is not a mistake.
func (g *PlanRegistry) RevokeAdminSession(token string) error {
	if token == "" {
		return nil
	}
	if _, err := g.db.ExecContext(context.Background(),
		"UPDATE admin_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
		time.Now().UTC().UnixNano(), adminTokenHash(token)); err != nil {
		return fmt.Errorf("control: revoking admin session: %w", err)
	}
	return nil
}

// PruneAdminSessions deletes sessions that expired more than a day ago. It is
// called on login so the table stays small without a background worker.
func (g *PlanRegistry) PruneAdminSessions() error {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).UnixNano()
	if _, err := g.db.ExecContext(context.Background(),
		"DELETE FROM admin_sessions WHERE expires_at < ?", cutoff); err != nil {
		return fmt.Errorf("control: pruning admin sessions: %w", err)
	}
	return nil
}

// newAdminToken returns an unguessable session identifier.
func newAdminToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("control: generating an admin token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// adminTokenHash hashes a session token for storage and lookup.
func adminTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
