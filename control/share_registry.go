package control

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Xunara Share: the platform-level registry of cross-organization machine
// shares (PROJECT_SPEC section 38).
//
// The registry is deliberately platform-scoped, not org-scoped: a share is a
// relationship between two organizations, so storing it inside one tenant's
// database would let that tenant's writes define the other tenant's state
// (AGENTS.md section 12). It holds routing keys and lifecycle only: node
// snapshots and synthetic identifiers stay in the organizations themselves.

// Share statuses.
const (
	// SharePending waits for the target identity to accept or reject.
	SharePending = "pending"
	// ShareAccepted is in force: both netmaps expose the peer pair.
	ShareAccepted = "accepted"
	// ShareRejected is terminal: the target declined.
	ShareRejected = "rejected"
	// ShareRevoked is terminal: either side withdrew.
	ShareRevoked = "revoked"
)

// Share lifecycle errors, mapped by the API layer to HTTP status codes.
var (
	// ErrShareNotFound is returned for an unknown share ID.
	ErrShareNotFound = errors.New("control: share not found")
	// ErrShareExists is returned when the same source node already has an
	// active share to the same target identity.
	ErrShareExists = errors.New("control: an active share already exists")
	// ErrShareState is returned when a lifecycle action does not apply to the
	// share's current status.
	ErrShareState = errors.New("control: share is not in a state for this action")
	// ErrShareTarget is returned when the caller is not the share's target.
	ErrShareTarget = errors.New("control: caller is not the share target")
)

// Share is one machine shared from a source organization to a user identity
// in a target organization. Timestamps are zero when the step did not happen;
// the wire view omits them.
type Share struct {
	// ID is the stable identifier, also the console/API handle.
	ID string
	// SourceOrg owns the shared machine.
	SourceOrg string
	// SourceNode is the machine's numeric ID in SourceOrg's state store.
	SourceNode int64
	// TargetOrg is the organization the target user must belong to.
	TargetOrg string
	// Provider and Subject are the target identity within TargetOrg
	// (AGENTS.md section 6: the identity key, never an email).
	Provider string
	Subject  string
	// Status is one of the Share* constants.
	Status string
	// CreatedBy is the source-organization user who created the share.
	CreatedBy int64
	CreatedAt time.Time

	AcceptedAt time.Time
	AcceptedBy int64
	RejectedAt time.Time
	RejectedBy int64
	RevokedAt  time.Time
	RevokedBy  int64
	// RevokedByOrg records which side revoked an accepted share, for audit.
	RevokedByOrg string
}

// Active reports whether the share still occupies its uniqueness slot.
func (s Share) Active() bool {
	return s.Status == SharePending || s.Status == ShareAccepted
}

// ShareFilter selects shares for listing. Zero fields do not filter, except
// TargetUser: when set it requires an accepted share bound to that user.
type ShareFilter struct {
	SourceOrg  string
	SourceNode int64
	TargetOrg  string
	TargetUser int64
	Provider   string
	Subject    string
	// Statuses limits the result when non-empty.
	Statuses []string
}

// ShareRegistryConfig configures the durable platform share registry.
type ShareRegistryConfig struct {
	// Path is the SQLite database file holding the share table.
	Path string
}

// ShareRegistry is the durable table of cross-organization shares.
type ShareRegistry struct {
	db *sql.DB
}

// shareMigrations are applied in order and tracked in this module's own
// schema_migrations table, like the other SQLite-backed modules.
var shareMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS shares (
	id             TEXT    PRIMARY KEY,
	source_org     TEXT    NOT NULL,
	source_node    INTEGER NOT NULL,
	target_org     TEXT    NOT NULL,
	provider       TEXT    NOT NULL,
	subject        TEXT    NOT NULL,
	status         TEXT    NOT NULL,
	created_by     INTEGER NOT NULL,
	created_at     INTEGER NOT NULL,
	accepted_at    INTEGER NOT NULL DEFAULT 0,
	accepted_by    INTEGER NOT NULL DEFAULT 0,
	rejected_at    INTEGER NOT NULL DEFAULT 0,
	rejected_by    INTEGER NOT NULL DEFAULT 0,
	revoked_at     INTEGER NOT NULL DEFAULT 0,
	revoked_by     INTEGER NOT NULL DEFAULT 0,
	revoked_by_org TEXT    NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_active
	ON shares(source_org, source_node, target_org, provider, subject)
	WHERE status IN ('pending', 'accepted');

CREATE INDEX IF NOT EXISTS idx_shares_source ON shares(source_org, source_node, status);
CREATE INDEX IF NOT EXISTS idx_shares_target ON shares(target_org, provider, subject, status);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(target_org, accepted_by, status);
`,
}

// OpenShareRegistry opens (creating if necessary) the registry and applies
// pending migrations.
func OpenShareRegistry(ctx context.Context, cfg ShareRegistryConfig) (*ShareRegistry, error) {
	if cfg.Path == "" {
		return nil, errors.New("control: share registry needs a database path")
	}
	if strings.ContainsAny(cfg.Path, "?#") {
		return nil, fmt.Errorf("control: unsupported character in database path %q", cfg.Path)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the share registry directory: %w", err)
	}

	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("control: opening the share registry: %w", err)
	}
	// One process owns this file; a single connection keeps the WAL honest
	// and avoids "database is locked" churn between the router's writers.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("control: enabling WAL: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("control: enabling foreign keys: %w", err)
	}
	registry := &ShareRegistry{db: db}
	if err := registry.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return registry, nil
}

// migrate applies pending schema versions.
func (r *ShareRegistry) migrate(ctx context.Context) error {
	var version int
	if err := r.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("control: reading the share schema version: %w", err)
	}
	if version > len(shareMigrations) {
		return fmt.Errorf("control: share schema version %d is newer than this build (%d)", version, len(shareMigrations))
	}
	for i := version; i < len(shareMigrations); i++ {
		if _, err := r.db.ExecContext(ctx, shareMigrations[i]); err != nil {
			return fmt.Errorf("control: applying share migration %d: %w", i+1, err)
		}
		if _, err := r.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return fmt.Errorf("control: recording share migration %d: %w", i+1, err)
		}
	}
	return nil
}

// Close releases the registry's database handle.
func (r *ShareRegistry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// newShareID returns a fresh random share identifier.
func newShareID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("control: generating a share id: %w", err)
	}
	return "shr_" + hex.EncodeToString(buf[:]), nil
}

// CreateShare stores a new pending share and returns it with its assigned ID
// and timestamp. The caller is responsible for validating the parties.
func (r *ShareRegistry) CreateShare(ctx context.Context, share Share, now time.Time) (Share, error) {
	if share.SourceOrg == "" || share.TargetOrg == "" || share.Provider == "" || share.Subject == "" {
		return Share{}, errors.New("control: share needs a source organization, a target organization and an identity")
	}
	if share.SourceNode <= 0 {
		return Share{}, errors.New("control: share needs a source node")
	}
	if share.Status == "" {
		share.Status = SharePending
	}
	if share.Status != SharePending {
		return Share{}, fmt.Errorf("control: new shares start pending, got %q", share.Status)
	}

	id, err := newShareID()
	if err != nil {
		return Share{}, err
	}
	share.ID = id
	share.CreatedAt = now.UTC()

	_, err = r.db.ExecContext(ctx, `
INSERT INTO shares (id, source_org, source_node, target_org, provider, subject, status, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		share.ID, share.SourceOrg, share.SourceNode, share.TargetOrg, share.Provider, share.Subject,
		share.Status, share.CreatedBy, share.CreatedAt.Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return Share{}, fmt.Errorf("%w: %w", ErrShareExists, err)
		}
		return Share{}, fmt.Errorf("control: storing share: %w", err)
	}
	return share, nil
}

// GetShare returns a share by ID.
func (r *ShareRegistry) GetShare(id string) (Share, bool) {
	row := r.db.QueryRow(`
SELECT id, source_org, source_node, target_org, provider, subject, status,
       created_by, created_at, accepted_at, accepted_by, rejected_at, rejected_by,
       revoked_at, revoked_by, revoked_by_org
FROM shares WHERE id = ?`, id)
	share, err := scanShare(row)
	if err != nil {
		return Share{}, false
	}
	return share, true
}

// ListShares returns matching shares, newest first (ID breaks ties so the
// order is total).
func (r *ShareRegistry) ListShares(filter ShareFilter) []Share {
	query := `
SELECT id, source_org, source_node, target_org, provider, subject, status,
       created_by, created_at, accepted_at, accepted_by, rejected_at, rejected_by,
       revoked_at, revoked_by, revoked_by_org
FROM shares`
	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		where = append(where, clause)
		args = append(args, value)
	}
	if filter.SourceOrg != "" {
		add("source_org = ?", filter.SourceOrg)
	}
	if filter.SourceNode != 0 {
		add("source_node = ?", filter.SourceNode)
	}
	if filter.TargetOrg != "" {
		add("target_org = ?", filter.TargetOrg)
	}
	if filter.TargetUser != 0 {
		add("accepted_by = ?", filter.TargetUser)
	}
	if filter.Provider != "" {
		add("provider = ?", filter.Provider)
	}
	if filter.Subject != "" {
		add("subject = ?", filter.Subject)
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, status := range filter.Statuses {
			placeholders[i] = "?"
			args = append(args, status)
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id ASC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Share
	for rows.Next() {
		share, err := scanShare(rows)
		if err != nil {
			return out
		}
		out = append(out, share)
	}
	return out
}

// AcceptShare binds a pending share to the accepting user. It fails when the
// share is unknown, not pending, or belongs to another organization.
func (r *ShareRegistry) AcceptShare(id, targetOrg string, user int64, now time.Time) (Share, error) {
	return r.decide(id, targetOrg, `
UPDATE shares SET status = ?, accepted_at = ?, accepted_by = ?
WHERE id = ? AND status = ?`, []any{ShareAccepted, now.UTC().Unix(), user, id, SharePending})
}

// RejectShare declines a pending share. It fails when the share is unknown,
// not pending, or belongs to another organization.
func (r *ShareRegistry) RejectShare(id, targetOrg string, user int64, now time.Time) (Share, error) {
	return r.decide(id, targetOrg, `
UPDATE shares SET status = ?, rejected_at = ?, rejected_by = ?
WHERE id = ? AND status = ?`, []any{ShareRejected, now.UTC().Unix(), user, id, SharePending})
}

// RevokeShare withdraws a pending or accepted share. Revoking an already
// revoked share is idempotent and returns the existing row.
func (r *ShareRegistry) RevokeShare(id, byOrg string, user int64, now time.Time) (Share, error) {
	share, ok := r.GetShare(id)
	if !ok {
		return Share{}, ErrShareNotFound
	}
	if byOrg != share.SourceOrg && byOrg != share.TargetOrg {
		return Share{}, ErrShareTarget
	}
	if share.Status == ShareRevoked {
		return share, nil
	}
	if share.Status != SharePending && share.Status != ShareAccepted {
		return Share{}, fmt.Errorf("%w: cannot revoke a %s share", ErrShareState, share.Status)
	}

	res, err := r.db.Exec(`
UPDATE shares SET status = ?, revoked_at = ?, revoked_by = ?, revoked_by_org = ?
WHERE id = ? AND status IN (?, ?)`,
		ShareRevoked, now.UTC().Unix(), user, byOrg, id, SharePending, ShareAccepted)
	if err != nil {
		return Share{}, fmt.Errorf("control: revoking share: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Lost a race with another decision; report the row we read.
		if current, ok := r.GetShare(id); ok {
			return current, nil
		}
		return Share{}, ErrShareNotFound
	}
	share.Status = ShareRevoked
	share.RevokedAt = now.UTC()
	share.RevokedBy = user
	share.RevokedByOrg = byOrg
	return share, nil
}

// decide applies one lifecycle transition under a conditional UPDATE, so two
// concurrent decisions cannot both win.
func (r *ShareRegistry) decide(id, targetOrg, update string, args []any) (Share, error) {
	share, ok := r.GetShare(id)
	if !ok {
		return Share{}, ErrShareNotFound
	}
	if share.TargetOrg != targetOrg {
		return Share{}, ErrShareTarget
	}
	if share.Status != SharePending {
		return Share{}, fmt.Errorf("%w: share is %s", ErrShareState, share.Status)
	}

	if _, err := r.db.Exec(update, args...); err != nil {
		return Share{}, fmt.Errorf("control: deciding share: %w", err)
	}
	updated, ok := r.GetShare(id)
	if !ok {
		return Share{}, ErrShareNotFound
	}
	return updated, nil
}

// scanShare reads one share row.
func scanShare(scan interface{ Scan(...any) error }) (Share, error) {
	var (
		share                                        Share
		createdAt, acceptedAt, rejectedAt, revokedAt int64
		acceptedBy, rejectedBy, revokedBy            int64
	)
	if err := scan.Scan(
		&share.ID, &share.SourceOrg, &share.SourceNode, &share.TargetOrg,
		&share.Provider, &share.Subject, &share.Status, &share.CreatedBy, &createdAt,
		&acceptedAt, &acceptedBy, &rejectedAt, &rejectedBy,
		&revokedAt, &revokedBy, &share.RevokedByOrg,
	); err != nil {
		return Share{}, err
	}
	share.CreatedAt = time.Unix(createdAt, 0).UTC()
	if acceptedAt != 0 {
		share.AcceptedAt = time.Unix(acceptedAt, 0).UTC()
	}
	if rejectedAt != 0 {
		share.RejectedAt = time.Unix(rejectedAt, 0).UTC()
	}
	if revokedAt != 0 {
		share.RevokedAt = time.Unix(revokedAt, 0).UTC()
	}
	if share.Status == ShareAccepted {
		share.AcceptedBy = acceptedBy
	}
	if share.Status == ShareRejected {
		share.RejectedBy = rejectedBy
	}
	if share.Status == ShareRevoked {
		share.RevokedBy = revokedBy
	}
	return share, nil
}

// validShareStatus reports whether status is a known lifecycle value.
func validShareStatus(status string) bool {
	return slices.Contains([]string{SharePending, ShareAccepted, ShareRejected, ShareRevoked}, status)
}
