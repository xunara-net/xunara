package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// migrations are applied in order; the applied count is tracked in
// PRAGMA user_version.
var migrations = []string{
	// v1: nodes and the counter table backing ID/address allocation.
	`
CREATE TABLE IF NOT EXISTS nodes (
	id          INTEGER PRIMARY KEY,
	stable_id   TEXT    NOT NULL UNIQUE,
	machine_key TEXT    NOT NULL,
	node_key    TEXT    NOT NULL UNIQUE,
	disco_key   TEXT    NOT NULL,
	user_id     INTEGER NOT NULL,
	hostname    TEXT    NOT NULL DEFAULT '',
	ipv4        TEXT,
	ipv6        TEXT,
	endpoints   TEXT    NOT NULL DEFAULT '[]',
	home_derp   INTEGER NOT NULL DEFAULT 0,
	cap_ver     INTEGER NOT NULL DEFAULT 0,
	hostinfo    BLOB,
	last_seen   INTEGER,
	expiry      INTEGER,
	created     INTEGER NOT NULL,
	method      TEXT    NOT NULL DEFAULT '',
	ephemeral   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_machine_key ON nodes(machine_key);

CREATE TABLE IF NOT EXISTS counters (
	name  TEXT    PRIMARY KEY,
	value INTEGER NOT NULL
);
`,

	// v2: pre-authentication keys.
	`
CREATE TABLE IF NOT EXISTS preauthkeys (
	id        INTEGER PRIMARY KEY,
	secret    TEXT    NOT NULL UNIQUE,
	user_id   INTEGER NOT NULL,
	reusable  INTEGER NOT NULL DEFAULT 0,
	ephemeral INTEGER NOT NULL DEFAULT 0,
	used      INTEGER NOT NULL DEFAULT 0,
	expiry    INTEGER,
	created   INTEGER NOT NULL,
	used_at   INTEGER
);
`,
}

// SQLiteStore is a durable [Store] backed by SQLite.
//
// All statements run on a single connection: SQLite allows one writer at a
// time, and serialising here keeps ID/address allocation atomic without
// sprinkling retries for SQLITE_BUSY through the call sites.
type SQLiteStore struct {
	db *sql.DB

	// mu makes "read counters, allocate, write" atomic across the two
	// statements CreateNode needs.
	mu sync.Mutex
}

// OpenSQLite opens (creating if necessary) a SQLite-backed store at path and
// applies pending migrations.
func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("state: unsupported character in database path %q", path)
	}

	dsn := "file:" + path +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("state: reading schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("state: database schema version %d is newer than this build (%d)", version, len(migrations))
	}

	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("state: starting migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("state: migration %d: %w", i+1, err)
		}
		// PRAGMA does not accept placeholders; i+1 is a bounded loop index.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("state: recording migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("state: committing migration %d: %w", i+1, err)
		}
	}
	return nil
}

var _ Store = (*SQLiteStore)(nil)

// nodeColumns is the column list every node SELECT and INSERT agrees on.
const nodeColumns = `id, stable_id, machine_key, node_key, disco_key, user_id, hostname,
	ipv4, ipv6, endpoints, home_derp, cap_ver, hostinfo, last_seen, expiry, created, method, ephemeral`

func (s *SQLiteStore) GetNodeByID(id NodeID) (Node, bool) {
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE id = ?", int64(id))
}

func (s *SQLiteStore) GetNodeByNodeKey(nk key.NodePublic) (Node, bool) {
	text, err := nk.MarshalText()
	if err != nil {
		return Node{}, false
	}
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE node_key = ?", string(text))
}

func (s *SQLiteStore) GetNodeByStableID(id string) (Node, bool) {
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE stable_id = ?", id)
}

func (s *SQLiteStore) GetNodesByMachineKey(mk key.MachinePublic) []Node {
	text, err := mk.MarshalText()
	if err != nil {
		return nil
	}

	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+nodeColumns+" FROM nodes WHERE machine_key = ? ORDER BY id", string(text))
	if err != nil {
		return nil
	}
	defer rows.Close()

	return collectNodes(rows)
}

func (s *SQLiteStore) ListNodes() []Node {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+nodeColumns+" FROM nodes ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	return collectNodes(rows)
}

func (s *SQLiteStore) queryNode(ctx context.Context, query string, args ...any) (Node, bool) {
	row := s.db.QueryRowContext(ctx, query, args...)
	n, err := scanNode(row)
	if err != nil {
		return Node{}, false
	}
	return n, true
}

func collectNodes(rows *sql.Rows) []Node {
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanNode(sc scanner) (Node, error) {
	var (
		id        int64
		stableID  string
		machineS  string
		nodeS     string
		discoS    string
		userID    int64
		hostname  string
		ipv4      sql.NullString
		ipv6      sql.NullString
		endpoints string
		homeDERP  int64
		capVer    int64
		hostinfo  []byte
		lastSeen  sql.NullInt64
		expiry    sql.NullInt64
		created   int64
		method    string
		ephemeral int64
	)

	err := sc.Scan(&id, &stableID, &machineS, &nodeS, &discoS, &userID, &hostname,
		&ipv4, &ipv6, &endpoints, &homeDERP, &capVer, &hostinfo, &lastSeen, &expiry,
		&created, &method, &ephemeral)
	if err != nil {
		return Node{}, err
	}

	n := Node{
		ID:        NodeID(id),
		StableID:  stableID,
		UserID:    tailcfg.UserID(userID),
		Hostname:  hostname,
		HomeDERP:  tailcfg.DERPRegionID(homeDERP),
		CapVer:    tailcfg.CapabilityVersion(capVer),
		Created:   time.Unix(0, created).UTC(),
		Method:    RegisterMethod(method),
		Ephemeral: ephemeral != 0,
	}

	if err := n.MachineKey.UnmarshalText([]byte(machineS)); err != nil {
		return Node{}, fmt.Errorf("state: parsing machine key: %w", err)
	}
	if err := n.NodeKey.UnmarshalText([]byte(nodeS)); err != nil {
		return Node{}, fmt.Errorf("state: parsing node key: %w", err)
	}
	if discoS != "" {
		if err := n.DiscoKey.UnmarshalText([]byte(discoS)); err != nil {
			return Node{}, fmt.Errorf("state: parsing disco key: %w", err)
		}
	}
	if ipv4.Valid {
		if n.IPv4, err = netip.ParseAddr(ipv4.String); err != nil {
			return Node{}, fmt.Errorf("state: parsing IPv4: %w", err)
		}
	}
	if ipv6.Valid {
		if n.IPv6, err = netip.ParseAddr(ipv6.String); err != nil {
			return Node{}, fmt.Errorf("state: parsing IPv6: %w", err)
		}
	}
	if lastSeen.Valid {
		t := time.Unix(0, lastSeen.Int64).UTC()
		n.LastSeen = &t
	}
	if expiry.Valid {
		n.Expiry = time.Unix(0, expiry.Int64).UTC()
	}
	if len(hostinfo) > 0 {
		var hi tailcfg.Hostinfo
		if err := json.Unmarshal(hostinfo, &hi); err != nil {
			return Node{}, fmt.Errorf("state: parsing hostinfo: %w", err)
		}
		n.Hostinfo = &hi
	}
	if err := decodeEndpoints(endpoints, &n); err != nil {
		return Node{}, err
	}

	return n, nil
}

func decodeEndpoints(encoded string, n *Node) error {
	if encoded == "" || encoded == "[]" {
		return nil
	}

	var raw []string
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return fmt.Errorf("state: parsing endpoints: %w", err)
	}

	n.Endpoints = make([]netip.AddrPort, 0, len(raw))
	for _, s := range raw {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("state: parsing endpoint %q: %w", s, err)
		}
		n.Endpoints = append(n.Endpoints, ap)
	}
	return nil
}

func encodeEndpoints(n Node) (string, error) {
	if len(n.Endpoints) == 0 {
		return "[]", nil
	}

	raw := make([]string, 0, len(n.Endpoints))
	for _, ap := range n.Endpoints {
		raw = append(raw, ap.String())
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("state: encoding endpoints: %w", err)
	}
	return string(b), nil
}

func (s *SQLiteStore) CreateNode(n *Node) error {
	if n == nil {
		return fmt.Errorf("state: nil node")
	}
	if n.NodeKey.IsZero() {
		return fmt.Errorf("state: node key is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: beginning create: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if n.StableID == "" {
		n.StableID = newStableID()
	}
	if n.Created.IsZero() {
		n.Created = time.Now().UTC()
	}

	nextID, err := nextCounter(ctx, tx, counterNextNodeID, 1)
	if err != nil {
		return err
	}
	n.ID = NodeID(nextID)

	if !n.IPv4.IsValid() {
		offset, err := nextCounter(ctx, tx, counterNextIPv4Offset, 1)
		if err != nil {
			return err
		}
		addr, ok := addrAtOffset(defaultIPv4Prefix, uint32(offset))
		if !ok {
			return fmt.Errorf("state: IPv4 space exhausted")
		}
		n.IPv4 = addr
	}
	if !n.IPv6.IsValid() {
		offset, err := nextCounter(ctx, tx, counterNextIPv6Offset, 1)
		if err != nil {
			return err
		}
		addr, ok := addrAtOffset(defaultIPv6Prefix, uint32(offset))
		if !ok {
			return fmt.Errorf("state: IPv6 space exhausted")
		}
		n.IPv6 = addr
	}

	endpoints, err := encodeEndpoints(*n)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO nodes (`+nodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(n.ID),
		n.StableID,
		textOf(n.MachineKey, ""),
		textOf(n.NodeKey, ""),
		textOf(n.DiscoKey, ""),
		int64(n.UserID),
		n.Hostname,
		nullableAddr(n.IPv4),
		nullableAddr(n.IPv6),
		endpoints,
		int64(n.HomeDERP),
		int64(n.CapVer),
		marshalHostinfo(n.Hostinfo),
		nullableTime(n.LastSeen),
		nullableTimePtr(n.Expiry),
		n.Created.UnixNano(),
		string(n.Method),
		boolToInt(n.Ephemeral),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrNodeKeyExists
		}
		return fmt.Errorf("state: inserting node: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) UpdateNode(n Node) error {
	endpoints, err := encodeEndpoints(n)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(context.Background(), `UPDATE nodes SET
			stable_id = ?, machine_key = ?, node_key = ?, disco_key = ?, user_id = ?,
			hostname = ?, ipv4 = ?, ipv6 = ?, endpoints = ?, home_derp = ?,
			cap_ver = ?, hostinfo = ?, last_seen = ?, expiry = ?, created = ?,
			method = ?, ephemeral = ?
		WHERE id = ?`,
		n.StableID,
		textOf(n.MachineKey, ""),
		textOf(n.NodeKey, ""),
		textOf(n.DiscoKey, ""),
		int64(n.UserID),
		n.Hostname,
		nullableAddr(n.IPv4),
		nullableAddr(n.IPv6),
		endpoints,
		int64(n.HomeDERP),
		int64(n.CapVer),
		marshalHostinfo(n.Hostinfo),
		nullableTime(n.LastSeen),
		nullableTimePtr(n.Expiry),
		n.Created.UnixNano(),
		string(n.Method),
		boolToInt(n.Ephemeral),
		int64(n.ID),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrNodeKeyExists
		}
		return fmt.Errorf("state: updating node %d: %w", n.ID, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: updating node %d: %w", n.ID, err)
	}
	if affected == 0 {
		return fmt.Errorf("state: node %d not found", n.ID)
	}
	return nil
}

func (s *SQLiteStore) DeleteNode(id NodeID) error {
	_, err := s.db.ExecContext(context.Background(), "DELETE FROM nodes WHERE id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("state: deleting node %d: %w", id, err)
	}
	return nil
}

// Counter names backing ID and address allocation.
const (
	counterNextNodeID     = "next_node_id"
	counterNextIPv4Offset = "next_ipv4_offset"
	counterNextIPv6Offset = "next_ipv6_offset"
)

// nextCounter returns the current value of a counter and advances it.
func nextCounter(ctx context.Context, tx *sql.Tx, name string, def int64) (int64, error) {
	var value int64
	err := tx.QueryRowContext(ctx, "SELECT value FROM counters WHERE name = ?", name).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		value = def
	case err != nil:
		return 0, fmt.Errorf("state: reading counter %s: %w", name, err)
	}

	next := value + 1
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO counters (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
		name, next); err != nil {
		return 0, fmt.Errorf("state: writing counter %s: %w", name, err)
	}
	return value, nil
}

func textOf(m interface{ MarshalText() ([]byte, error) }, fallback string) string {
	b, err := m.MarshalText()
	if err != nil {
		return fallback
	}
	return string(b)
}

func nullableAddr(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a.String()
}

func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func nullableTimePtr(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func marshalHostinfo(hi *tailcfg.Hostinfo) any {
	if hi == nil {
		return nil
	}
	b, err := json.Marshal(hi)
	if err != nil {
		return nil
	}
	return b
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
