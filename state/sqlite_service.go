package state

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// ReplaceNodeServices implements [ServiceStore].
func (s *SQLiteStore) ReplaceNodeServices(id NodeID, services []Service) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: replacing services of node %d: %w", id, err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE id = ?", int64(id)).Scan(&exists); err != nil {
		return fmt.Errorf("state: looking up node %d: %w", id, err)
	}
	if exists == 0 {
		return errUnknownNode(id)
	}

	// Remember creation times so a purely cosmetic republish does not reset
	// them; published names are unique, so the map is unambiguous.
	created := make(map[string]time.Time)
	rows, err := tx.QueryContext(ctx, "SELECT name, created FROM node_services WHERE node_id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	for rows.Next() {
		var name string
		var at int64
		if err := rows.Scan(&name, &at); err != nil {
			rows.Close()
			return fmt.Errorf("state: scanning service of node %d: %w", id, err)
		}
		created[name] = time.Unix(at, 0).UTC()
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	rows.Close()

	if _, err := tx.ExecContext(ctx, "DELETE FROM node_services WHERE node_id = ?", int64(id)); err != nil {
		return fmt.Errorf("state: clearing services of node %d: %w", id, err)
	}

	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if seen[svc.Name] {
			return errServiceNameTaken(svc.Name)
		}
		seen[svc.Name] = true
	}

	now := time.Now().UTC()
	ordered := slices.Clone(services)
	slices.SortFunc(ordered, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	for _, svc := range ordered {
		metadata, err := json.Marshal(svc.Metadata)
		if err != nil {
			return fmt.Errorf("state: encoding metadata of service %q: %w", svc.Name, err)
		}
		if svc.Metadata == nil {
			metadata = []byte("{}")
		}
		createdAt := svc.Created
		if prev, ok := created[svc.Name]; ok {
			createdAt = prev
		}
		if createdAt.IsZero() {
			createdAt = now
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_services (node_id, name, protocol, port, metadata, created, updated)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			int64(id), svc.Name, svc.Protocol, int(svc.Port), string(metadata),
			createdAt.Unix(), now.Unix()); err != nil {
			if isUniqueViolation(err) {
				return errServiceNameTaken(svc.Name)
			}
			return fmt.Errorf("state: storing service %q on node %d: %w", svc.Name, id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: replacing services of node %d: %w", id, err)
	}
	return nil
}

// ListServices implements [ServiceStore].
func (s *SQLiteStore) ListServices() []Service {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT node_id, name, protocol, port, metadata, created, updated FROM node_services ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			continue
		}
		out = append(out, svc)
	}
	return out
}

// ServicesForNode implements [ServiceStore].
func (s *SQLiteStore) ServicesForNode(id NodeID) ([]Service, error) {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT node_id, name, protocol, port, metadata, created, updated FROM node_services WHERE node_id = ? ORDER BY name",
		int64(id))
	if err != nil {
		return nil, fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	defer rows.Close()

	out := []Service{}
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			return nil, fmt.Errorf("state: scanning service of node %d: %w", id, err)
		}
		out = append(out, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	return out, nil
}

// GetServiceByName implements [ServiceStore].
func (s *SQLiteStore) GetServiceByName(name string) (Service, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT node_id, name, protocol, port, metadata, created, updated FROM node_services WHERE name = ?", name)
	svc, err := scanService(row)
	if err != nil {
		return Service{}, false
	}
	return svc, true
}

// NodeServiceCounts implements [ServiceStore].
func (s *SQLiteStore) NodeServiceCounts() (map[NodeID]int, error) {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT node_id, COUNT(*) FROM node_services GROUP BY node_id")
	if err != nil {
		return nil, fmt.Errorf("state: counting services: %w", err)
	}
	defer rows.Close()

	counts := make(map[NodeID]int)
	for rows.Next() {
		var (
			id    int64
			count int
		)
		if err := rows.Scan(&id, &count); err != nil {
			return nil, fmt.Errorf("state: scanning service counts: %w", err)
		}
		counts[NodeID(id)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: counting services: %w", err)
	}
	return counts, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanService reads one service row.
func scanService(row rowScanner) (Service, error) {
	var (
		svc      Service
		nodeID   int64
		port     int
		metadata string
		created  int64
		updated  int64
	)
	if err := row.Scan(&nodeID, &svc.Name, &svc.Protocol, &port, &metadata, &created, &updated); err != nil {
		return Service{}, err
	}
	svc.NodeID = NodeID(nodeID)
	svc.Port = uint16(port)
	svc.Created = time.Unix(created, 0).UTC()
	svc.Updated = time.Unix(updated, 0).UTC()
	if metadata != "" {
		var meta map[string]string
		if err := json.Unmarshal([]byte(metadata), &meta); err == nil && len(meta) > 0 {
			svc.Metadata = meta
		}
	}
	return svc, nil
}
