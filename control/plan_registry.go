package control

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xunara/xunara/netspace"
	"github.com/xunara/xunara/plan"
)

// Tenant plans and tenant network blocks (PROJECT_SPEC section 54).
//
// A Xunara deployment sells plans; a plan is a set of quotas and feature
// switches (package plan), and this file holds the two facts a plan needs to
// become real for one tenant: which plan the tenant is on, and which address
// range its devices are allocated from.
//
// The registry is the platform layer's memory, not the control plane's: it
// lives in its own SQLite file, is keyed by organization ID, and is only
// opened when the deployment actually sells plans (multi-tenant deployments
// and single-tenant deployments that pass -plans). Without it every tenant is
// on [plan.UnlimitedPlan] and nothing changes for a self-hosted installation.
//
// Assignment is deliberately a plain row per tenant with no history: the audit
// log records who changed what, the row records the current state. Two sources
// of truth for "which plan is this tenant on" would be one too many.

// TenantPlan is one tenant's commercial state.
type TenantPlan struct {
	// OrgID is the organization (tenant) this row describes.
	OrgID string
	// PlanID names a plan in the catalog.
	PlanID string
	// NetworkPrefix is the tailnet address range devices are allocated from,
	// in canonical text form. Empty means "the deployment default".
	NetworkPrefix string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Errors the platform API and the console map to HTTP responses.
var (
	// ErrPlanUnknown is returned when an assignment names a plan the catalog
	// does not have.
	ErrPlanUnknown = errors.New("control: unknown plan")
	// ErrNetworkNotAllowed is returned when a plan forbids a custom tailnet
	// range.
	ErrNetworkNotAllowed = errors.New("control: the plan does not allow a custom network range")
	// ErrNetworkConflict is returned when a range overlaps another tenant's.
	ErrNetworkConflict = errors.New("control: the network range is already in use by another tailnet")
	// ErrNoNetworkBlock is returned when the deployment's pool is exhausted.
	ErrNoNetworkBlock = errors.New("control: the deployment has no free network block left")
)

// planRegistryMigrations are applied in order and tracked with PRAGMA
// user_version on the registry's own database file.
var planRegistryMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS tenant_plans (
	org_id         TEXT    PRIMARY KEY,
	plan_id        TEXT    NOT NULL,
	network_prefix TEXT    NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL
);
`,
}

// PlanRegistryConfig configures the tenant plan registry.
type PlanRegistryConfig struct {
	// Path is the SQLite database file holding assignments.
	Path string
	// Catalog is the set of sellable plans. Nil uses the built-in catalog.
	Catalog *plan.Catalog
	// Pool is the range tenant network blocks are carved from. The zero value
	// disables automatic allocation: tenants then keep the built-in default
	// range unless an operator assigns one explicitly.
	Pool netspace.Pool
	// Reserved lists ranges no tenant may be given, on top of the globally
	// reserved ranges netspace knows about. A deployment puts its internal
	// networks here.
	Reserved []netip.Prefix
}

// PlanRegistry is the durable table of tenant plan assignments.
type PlanRegistry struct {
	cfg PlanRegistryConfig
	cat *plan.Catalog
	db  *sql.DB
}

// OpenPlanRegistry opens (creating if necessary) the registry and applies
// pending migrations.
func OpenPlanRegistry(ctx context.Context, cfg PlanRegistryConfig) (*PlanRegistry, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("control: plan registry needs a database path")
	}
	if strings.ContainsAny(cfg.Path, "?#") {
		return nil, fmt.Errorf("control: unsupported character in database path %q", cfg.Path)
	}
	cat := cfg.Catalog
	if cat == nil {
		cat = plan.DefaultCatalog()
	}
	if len(cat.List()) == 0 {
		return nil, errors.New("control: plan registry needs a catalog with at least one plan")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the plan registry directory: %w", err)
	}

	dsn := "file:" + cfg.Path +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("control: opening %s: %w", cfg.Path, err)
	}
	db.SetMaxOpenConns(1)

	registry := &PlanRegistry{cfg: cfg, cat: cat, db: db}
	if err := registry.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return registry, nil
}

func (g *PlanRegistry) migrate(ctx context.Context) error {
	var version int
	if err := g.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("control: reading plan registry schema version: %w", err)
	}
	if version > len(planRegistryMigrations) {
		return fmt.Errorf("control: plan registry schema version %d is newer than this build understands", version)
	}
	for i := version; i < len(planRegistryMigrations); i++ {
		if _, err := g.db.ExecContext(ctx, planRegistryMigrations[i]); err != nil {
			return fmt.Errorf("control: applying plan registry migration %d: %w", i+1, err)
		}
		if _, err := g.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			return fmt.Errorf("control: recording plan registry migration %d: %w", i+1, err)
		}
	}
	return nil
}

// Close closes the registry database.
func (g *PlanRegistry) Close() error { return g.db.Close() }

// Catalog returns the plans this deployment sells, in catalog order.
func (g *PlanRegistry) Catalog() *plan.Catalog { return g.cat }

// Pool returns the deployment's tenant network pool.
func (g *PlanRegistry) Pool() netspace.Pool { return g.cfg.Pool }

// Reserved returns the ranges no tenant may hold, including the deployment's
// own internal ranges.
func (g *PlanRegistry) Reserved() []netip.Prefix {
	out := netspace.Reserved()
	return append(out, g.cfg.Reserved...)
}

// List returns every tenant with an assignment, oldest first.
func (g *PlanRegistry) List(ctx context.Context) ([]TenantPlan, error) {
	rows, err := g.db.QueryContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans ORDER BY created_at, org_id")
	if err != nil {
		return nil, fmt.Errorf("control: listing tenant plans: %w", err)
	}
	defer rows.Close()

	var out []TenantPlan
	for rows.Next() {
		assignment, err := scanTenantPlan(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("control: listing tenant plans: %w", err)
		}
		out = append(out, assignment)
	}
	return out, rows.Err()
}

// Get returns one tenant's assignment. An unassigned tenant reports false.
func (g *PlanRegistry) Get(ctx context.Context, orgID string) (TenantPlan, bool, error) {
	row := g.db.QueryRowContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans WHERE org_id = ?", orgID)
	assignment, err := scanTenantPlan(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPlan{}, false, nil
	}
	if err != nil {
		return TenantPlan{}, false, fmt.Errorf("control: reading tenant plan %q: %w", orgID, err)
	}
	return assignment, true, nil
}

// Assignment returns a tenant's state with defaults filled in: an unassigned
// tenant is on the catalog's default plan with no explicit network block.
func (g *PlanRegistry) Assignment(ctx context.Context, orgID string) (TenantPlan, error) {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	if !ok {
		return TenantPlan{OrgID: orgID, PlanID: g.cat.Default().ID}, nil
	}
	return assignment, nil
}

// Plan returns the plan a tenant is on. An unassigned tenant, or one whose
// assignment names a plan the catalog no longer has, falls back to the
// catalog's default: a deleted plan must not leave a tenant without rules.
func (g *PlanRegistry) Plan(ctx context.Context, orgID string) plan.Plan {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil || !ok {
		return g.cat.Default()
	}
	p, ok := g.cat.Get(assignment.PlanID)
	if !ok {
		return g.cat.Default()
	}
	return p
}

// NetworkPrefix returns the address range a tenant's devices are allocated
// from. ok is false when the tenant has no explicit block and the deployment
// default applies.
func (g *PlanRegistry) NetworkPrefix(ctx context.Context, orgID string) (netip.Prefix, bool) {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil || !ok || assignment.NetworkPrefix == "" {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(assignment.NetworkPrefix)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// AssignPlan puts a tenant on a plan. Existing values are replaced; the
// network block is kept unless the new plan forbids the tenant's custom range,
// in which case a block is allocated from the pool again (devices keep the
// addresses they already have: a plan change never re-addresses a live
// tailnet).
func (g *PlanRegistry) AssignPlan(ctx context.Context, orgID, planID string) (TenantPlan, error) {
	next, ok := g.cat.Get(planID)
	if !ok {
		return TenantPlan{}, fmt.Errorf("%w: %q", ErrPlanUnknown, planID)
	}
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: assigning plan %q to %q: %w", planID, orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: planID, CreatedAt: now}
	if ok {
		assignment.NetworkPrefix = current.NetworkPrefix
		assignment.CreatedAt = current.CreatedAt
	}
	if assignment.NetworkPrefix != "" && !next.AllowCustomCIDR {
		// The tenant is downgrading off a custom range. Keep the range only
		// when it came from the deployment's pool (it is a pool block, so it
		// was not the tenant's choice); otherwise hand back a pool block.
		prefix, err := netip.ParsePrefix(assignment.NetworkPrefix)
		if err != nil {
			return TenantPlan{}, fmt.Errorf("control: stored network range %q of %q is not a prefix: %w", assignment.NetworkPrefix, orgID, err)
		}
		if !g.cfg.Pool.Contains(prefix) {
			block, err := g.allocateTx(ctx, tx, orgID)
			if err != nil {
				return TenantPlan{}, err
			}
			assignment.NetworkPrefix = block.String()
		}
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: assigning plan %q to %q: %w", planID, orgID, err)
	}
	return assignment, nil
}

// Allocate gives a tenant the default plan and a free block of the
// deployment's pool. It is what a hosted deployment calls when an account
// signs up. Calling it for a tenant that already has a block is a no-op for
// the network half.
func (g *PlanRegistry) Allocate(ctx context.Context, orgID string) (TenantPlan, error) {
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: allocating tenant %q: %w", orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: g.cat.Default().ID, CreatedAt: now, UpdatedAt: now}
	if ok {
		assignment = current
		if assignment.PlanID == "" {
			assignment.PlanID = g.cat.Default().ID
		}
	}
	if assignment.NetworkPrefix == "" && !g.cfg.Pool.Zero() {
		block, err := g.allocateTx(ctx, tx, orgID)
		if err != nil {
			return TenantPlan{}, err
		}
		assignment.NetworkPrefix = block.String()
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: allocating tenant %q: %w", orgID, err)
	}
	return assignment, nil
}

// SetNetwork assigns a tenant's tailnet address range by hand. The plan must
// allow custom ranges, the range must be legal (netspace) and it must not
// overlap another tenant's range or the network block the deployment keeps for
// itself. Passing an invalid prefix clears the custom range, which restores
// the automatically allocated block (or the deployment default).
func (g *PlanRegistry) SetNetwork(ctx context.Context, orgID string, prefix netip.Prefix) (TenantPlan, error) {
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: setting network range of %q: %w", orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: g.cat.Default().ID, CreatedAt: now}
	if ok {
		assignment = current
		if assignment.PlanID == "" {
			assignment.PlanID = g.cat.Default().ID
		}
	}

	if !prefix.IsValid() {
		// Clearing: fall back to a pool block, or to the deployment default
		// when the deployment runs no pool.
		if !g.cfg.Pool.Zero() {
			block, err := g.allocateTx(ctx, tx, orgID)
			if err != nil {
				return TenantPlan{}, err
			}
			assignment.NetworkPrefix = block.String()
		} else {
			assignment.NetworkPrefix = ""
		}
	} else {
		tenantPlan, ok := g.cat.Get(assignment.PlanID)
		if !ok {
			tenantPlan = g.cat.Default()
		}
		if !tenantPlan.AllowCustomCIDR {
			return TenantPlan{}, fmt.Errorf("%w: plan %s", ErrNetworkNotAllowed, tenantPlan.ID)
		}
		normalized, err := netspace.ValidateTenantPrefix(prefix, g.cfg.Reserved)
		if err != nil {
			return TenantPlan{}, orgInvalidf("%v", err)
		}
		used, err := g.usedNetworksTx(ctx, tx, orgID)
		if err != nil {
			return TenantPlan{}, err
		}
		if other, overlap := netspace.FirstOverlap(normalized, used); overlap {
			return TenantPlan{}, fmt.Errorf("%w (%s)", ErrNetworkConflict, other)
		}
		assignment.NetworkPrefix = normalized.String()
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: setting network range of %q: %w", orgID, err)
	}
	return assignment, nil
}

// Delete drops a tenant's assignment, which returns it to the catalog default.
func (g *PlanRegistry) Delete(ctx context.Context, orgID string) error {
	if _, err := g.db.ExecContext(ctx, "DELETE FROM tenant_plans WHERE org_id = ?", orgID); err != nil {
		return fmt.Errorf("control: deleting tenant plan %q: %w", orgID, err)
	}
	return nil
}

// allocateTx picks the lowest free block of the pool inside a transaction.
// Running inside the writer's transaction is what makes two concurrent
// sign-ups agree on which block is free.
func (g *PlanRegistry) allocateTx(ctx context.Context, tx *sql.Tx, orgID string) (netip.Prefix, error) {
	used, err := g.usedNetworksTx(ctx, tx, orgID)
	if err != nil {
		return netip.Prefix{}, err
	}
	block, err := g.cfg.Pool.Allocate(g.Reserved(), used)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrNoNetworkBlock, err)
	}
	return block, nil
}

// usedNetworksTx lists the network ranges other tenants hold.
func (g *PlanRegistry) usedNetworksTx(ctx context.Context, tx *sql.Tx, excludeOrg string) ([]netip.Prefix, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT network_prefix FROM tenant_plans WHERE org_id <> ? AND network_prefix <> ''", excludeOrg)
	if err != nil {
		return nil, fmt.Errorf("control: listing allocated network ranges: %w", err)
	}
	defer rows.Close()

	var out []netip.Prefix
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("control: listing allocated network ranges: %w", err)
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("control: stored network range %q is not a prefix: %w", raw, err)
		}
		out = append(out, prefix)
	}
	return out, rows.Err()
}

// getTenantPlanTx reads one assignment inside a transaction.
func getTenantPlanTx(ctx context.Context, tx *sql.Tx, orgID string) (TenantPlan, bool, error) {
	row := tx.QueryRowContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans WHERE org_id = ?", orgID)
	assignment, err := scanTenantPlan(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPlan{}, false, nil
	}
	if err != nil {
		return TenantPlan{}, false, fmt.Errorf("control: reading tenant plan %q: %w", orgID, err)
	}
	return assignment, true, nil
}

// upsertTenantPlanTx writes one assignment inside a transaction.
func upsertTenantPlanTx(ctx context.Context, tx *sql.Tx, assignment TenantPlan) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO tenant_plans (org_id, plan_id, network_prefix, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(org_id) DO UPDATE SET
			plan_id        = excluded.plan_id,
			network_prefix = excluded.network_prefix,
			updated_at     = excluded.updated_at`,
		assignment.OrgID, assignment.PlanID, assignment.NetworkPrefix,
		assignment.CreatedAt.UnixNano(), assignment.UpdatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("control: storing tenant plan %q: %w", assignment.OrgID, err)
	}
	return nil
}

// scanTenantPlan reads one row in the canonical column order.
func scanTenantPlan(scan func(...any) error) (TenantPlan, error) {
	var (
		assignment        TenantPlan
		created, modified int64
	)
	if err := scan(&assignment.OrgID, &assignment.PlanID, &assignment.NetworkPrefix, &created, &modified); err != nil {
		return TenantPlan{}, err
	}
	assignment.CreatedAt = time.Unix(0, created).UTC()
	assignment.UpdatedAt = time.Unix(0, modified).UTC()
	return assignment, nil
}
