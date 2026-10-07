package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// identityMigrations are applied in order and tracked in the module's own
// schema_migrations table, so the identity tables can share a database file
// with another module's migrations without fighting over PRAGMA user_version.
var identityMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS users (
	id          INTEGER PRIMARY KEY,
	login_name  TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	display_name TEXT   NOT NULL DEFAULT '',
	email       TEXT    NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS external_identities (
	provider_id  TEXT    NOT NULL,
	subject      TEXT    NOT NULL,
	user_id      INTEGER NOT NULL,
	email        TEXT    NOT NULL DEFAULT '',
	display_name TEXT    NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL,
	PRIMARY KEY (provider_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);

CREATE TABLE IF NOT EXISTS audit_events (
	id     INTEGER PRIMARY KEY,
	ts     INTEGER NOT NULL,
	actor  TEXT    NOT NULL DEFAULT '',
	action TEXT    NOT NULL,
	target TEXT    NOT NULL DEFAULT '',
	detail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);
`,

	// v2: the trust-plane state machine: login transactions, browser
	// sessions, and device approvals. Three tables, three objects: they share
	// nothing but identifiers (AGENTS.md section 10).
	`
CREATE TABLE IF NOT EXISTS auth_transactions (
	id                   TEXT    PRIMARY KEY,
	provider_id          TEXT    NOT NULL,
	state                TEXT    NOT NULL,
	nonce                TEXT    NOT NULL,
	pkce_verifier        TEXT    NOT NULL,
	pkce_challenge       TEXT    NOT NULL,
	pkce_method          TEXT    NOT NULL,
	redirect_uri         TEXT    NOT NULL,
	return_to            TEXT    NOT NULL DEFAULT '',
	requested_action     TEXT    NOT NULL DEFAULT '',
	machine_login_id     TEXT    NOT NULL DEFAULT '',
	browser_session_hash TEXT    NOT NULL,
	created_at           INTEGER NOT NULL,
	expires_at           INTEGER NOT NULL,
	consumed_at          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_auth_transactions_expires ON auth_transactions(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
	id             TEXT    PRIMARY KEY,
	token_hash     TEXT    NOT NULL UNIQUE,
	user_id        INTEGER NOT NULL,
	auth_method    TEXT    NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL,
	last_seen_at   INTEGER,
	revoked_at     INTEGER,
	revoked_reason TEXT    NOT NULL DEFAULT '',
	rotated_from   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS device_authorizations (
	id               TEXT    PRIMARY KEY,
	machine_key      TEXT    NOT NULL,
	node_key         TEXT    NOT NULL,
	user_id          INTEGER,
	approved_by      INTEGER,
	state            TEXT    NOT NULL,
	requested_action TEXT    NOT NULL DEFAULT '',
	client_metadata  TEXT    NOT NULL DEFAULT '',
	created_at       INTEGER NOT NULL,
	expires_at       INTEGER NOT NULL,
	approved_at      INTEGER,
	denied_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_device_authorizations_node ON device_authorizations(node_key);
CREATE INDEX IF NOT EXISTS idx_device_authorizations_expires ON device_authorizations(expires_at);
`,

	// v3: service identities. An API key authenticates automation; it is not
	// a user, a session or a device.
	`
CREATE TABLE IF NOT EXISTS api_keys (
	id           TEXT    PRIMARY KEY,
	token_hash   TEXT    NOT NULL UNIQUE,
	name         TEXT    NOT NULL,
	user_id      INTEGER NOT NULL,
	scopes       TEXT    NOT NULL,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER,
	last_used_at INTEGER,
	revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
`,

	// v4: SSH check mode (hold and delegate). A held SSH session is its own
	// object, bound to the exact (source, destination) node pair; the
	// per-pair approval timestamps are what auto-approval reads. Neither is a
	// server-local map: any instance can serve the long poll (AGENTS.md 9/10).
	`
CREATE TABLE IF NOT EXISTS ssh_check_sessions (
	id          TEXT    PRIMARY KEY,
	src_node_id INTEGER NOT NULL,
	dst_node_id INTEGER NOT NULL,
	local_user  TEXT    NOT NULL DEFAULT '',
	verdict     TEXT    NOT NULL,
	decided_by  INTEGER,
	decided_at  INTEGER,
	consumed_at INTEGER,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssh_check_sessions_pair ON ssh_check_sessions(src_node_id, dst_node_id);
CREATE INDEX IF NOT EXISTS idx_ssh_check_sessions_expires ON ssh_check_sessions(expires_at);

CREATE TABLE IF NOT EXISTS ssh_check_auth (
	src_node_id INTEGER NOT NULL,
	dst_node_id INTEGER NOT NULL,
	authed_at   INTEGER NOT NULL,
	PRIMARY KEY (src_node_id, dst_node_id)
);
`,

	// v5: platform roles. A human user's role gates the console and the
	// platform API; it never changes what an official client may do on the
	// wire. Existing users are promoted to owner because, before roles
	// existed, every signed-in user could already do everything.
	`
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
UPDATE users SET role = 'owner';
`,

	// v6: webhook delivery cursors. A webhook endpoint consumes the durable
	// audit log; the cursor is what lets delivery resume after a restart
	// without a server-local queue (AGENTS.md section 9).
	`
CREATE TABLE IF NOT EXISTS webhook_cursors (
	endpoint      TEXT    PRIMARY KEY,
	last_event_id INTEGER NOT NULL DEFAULT 0,
	updated_at    INTEGER NOT NULL
);
`,

	// v7: native-client (Xunara Agent) credentials. An agent token is bound
	// to one node's machine and node keys: it is machine identity, never a
	// human or service identity (AGENTS.md section 5).
	`
CREATE TABLE IF NOT EXISTS agent_tokens (
	id           TEXT    PRIMARY KEY,
	node_id      INTEGER NOT NULL,
	machine_key  TEXT    NOT NULL,
	node_key     TEXT    NOT NULL,
	token_hash   TEXT    NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL DEFAULT 0,
	last_used_at INTEGER NOT NULL DEFAULT 0,
	revoked_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_node ON agent_tokens(node_id);
`,
}

// SQLiteStore is a durable [Store] sharing the control plane's database.
//
// The caller keeps ownership of the *sql.DB it passes in (one connection pool
// for the whole process keeps SQLite's single writer serialised).
type SQLiteStore struct {
	db *sql.DB
}

var _ Store = (*SQLiteStore)(nil)

// NewSQLiteStore migrates the identity tables and returns a store on db.
func NewSQLiteStore(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if db == nil {
		return nil, fmt.Errorf("identity: nil database handle")
	}

	s := &SQLiteStore{db: db}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			module  TEXT    PRIMARY KEY,
			version INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("identity: creating migration table: %w", err)
	}

	var version int
	err := s.db.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations WHERE module = 'identity'").Scan(&version)
	switch {
	case err == sql.ErrNoRows:
		version = 0
	case err != nil:
		return fmt.Errorf("identity: reading schema version: %w", err)
	}
	if version > len(identityMigrations) {
		return fmt.Errorf("identity: schema version %d is newer than this build (%d)",
			version, len(identityMigrations))
	}

	for i := version; i < len(identityMigrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("identity: starting migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, identityMigrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("identity: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (module, version) VALUES ('identity', ?)
			 ON CONFLICT(module) DO UPDATE SET version = excluded.version`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("identity: recording migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("identity: committing migration %d: %w", i+1, err)
		}
	}
	return nil
}

const userColumns = "id, login_name, display_name, email, role, created_at, updated_at"

// CreateUser implements [UserStore].
func (s *SQLiteStore) CreateUser(u *User) error {
	if u == nil || strings.TrimSpace(u.LoginName) == "" {
		return fmt.Errorf("identity: login name is required")
	}

	if !u.Role.Valid() {
		u.Role = RoleMember
	}

	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	res, err := s.db.ExecContext(context.Background(),
		"INSERT INTO users (login_name, display_name, email, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		u.LoginName, u.DisplayName, u.Email, string(u.Role), u.CreatedAt.UnixNano(), u.UpdatedAt.UnixNano())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrLoginNameTaken
		}
		return fmt.Errorf("identity: creating user: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("identity: reading user ID: %w", err)
	}
	u.ID = tailcfg.UserID(id)
	return nil
}

// GetUser implements [UserStore].
func (s *SQLiteStore) GetUser(id tailcfg.UserID) (User, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+userColumns+" FROM users WHERE id = ?", int64(id))
	u, err := scanUser(row)
	if err != nil {
		return User{}, false
	}
	return u, true
}

// GetUserByLoginName implements [UserStore].
func (s *SQLiteStore) GetUserByLoginName(login string) (User, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+userColumns+" FROM users WHERE login_name = ? COLLATE NOCASE", login)
	u, err := scanUser(row)
	if err != nil {
		return User{}, false
	}
	return u, true
}

// ListUsers implements [UserStore].
func (s *SQLiteStore) ListUsers() []User {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+userColumns+" FROM users ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil
		}
		out = append(out, u)
	}
	return out
}

// UpdateUser implements [UserStore].
func (s *SQLiteStore) UpdateUser(u User) error {
	u.UpdatedAt = time.Now().UTC()

	if !u.Role.Valid() {
		u.Role = RoleMember
	}

	res, err := s.db.ExecContext(context.Background(),
		`UPDATE users SET login_name = ?, display_name = ?, email = ?, role = ?, created_at = ?, updated_at = ?
		 WHERE id = ?`,
		u.LoginName, u.DisplayName, u.Email, string(u.Role), u.CreatedAt.UnixNano(), u.UpdatedAt.UnixNano(), int64(u.ID))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrLoginNameTaken
		}
		return fmt.Errorf("identity: updating user %d: %w", u.ID, err)
	}
	if affected, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("identity: updating user %d: %w", u.ID, err)
	} else if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

// DeleteUser implements [UserStore].
//
// The external identity links are deleted with the user: a dangling link
// pointing at a missing user would be a login failure waiting to happen.
func (s *SQLiteStore) DeleteUser(id tailcfg.UserID) error {
	ctx := context.Background()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity: starting user deletion: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM external_identities WHERE user_id = ?", int64(id)); err != nil {
		return fmt.Errorf("identity: deleting external identities of user %d: %w", id, err)
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("identity: deleting user %d: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: deleting user %d: %w", id, err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identity: committing user deletion: %w", err)
	}
	return nil
}

func scanUser(sc scanner) (User, error) {
	var (
		id        int64
		login     string
		display   string
		email     string
		role      string
		createdAt int64
		updatedAt int64
	)
	if err := sc.Scan(&id, &login, &display, &email, &role, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	return User{
		ID:          tailcfg.UserID(id),
		LoginName:   login,
		DisplayName: display,
		Email:       email,
		Role:        Role(role),
		CreatedAt:   time.Unix(0, createdAt).UTC(),
		UpdatedAt:   time.Unix(0, updatedAt).UTC(),
	}, nil
}
