package state

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SetNodeDeviceAttrs implements [DeviceAttrStore].
func (s *SQLiteStore) SetNodeDeviceAttrs(id NodeID, update map[string]any) error {
	if len(update) == 0 {
		return nil
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: updating device attributes for node %d: %w", id, err)
	}
	defer tx.Rollback()

	now := time.Now().UTC().Unix()
	// A single map iteration order is fine here: the transaction makes the
	// batch atomic, so a reader never observes a partial update.
	for name, value := range update {
		if value == nil {
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM node_device_attrs WHERE node_id = ? AND attr = ?", int64(id), name); err != nil {
				return fmt.Errorf("state: deleting device attribute %q from node %d: %w", name, id, err)
			}
			continue
		}

		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("state: encoding device attribute %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_device_attrs (node_id, attr, value, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(node_id, attr) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			int64(id), name, string(raw), now); err != nil {
			return fmt.Errorf("state: storing device attribute %q on node %d: %w", name, id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: updating device attributes for node %d: %w", id, err)
	}
	return nil
}

// NodeDeviceAttrs implements [DeviceAttrStore].
func (s *SQLiteStore) NodeDeviceAttrs(id NodeID) (map[string]any, error) {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT attr, value FROM node_device_attrs WHERE node_id = ? ORDER BY attr", int64(id))
	if err != nil {
		return nil, fmt.Errorf("state: reading device attributes of node %d: %w", id, err)
	}
	defer rows.Close()

	attrs := make(map[string]any)
	for rows.Next() {
		var name, raw string
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, fmt.Errorf("state: scanning device attribute of node %d: %w", id, err)
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			// A value this build cannot decode is skipped rather than poisoning
			// the whole set.
			continue
		}
		attrs[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading device attributes of node %d: %w", id, err)
	}
	if len(attrs) == 0 {
		return nil, nil
	}
	return attrs, nil
}

// NodeDeviceAttrCounts implements [DeviceAttrStore].
func (s *SQLiteStore) NodeDeviceAttrCounts() (map[NodeID]int, error) {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT node_id, COUNT(*) FROM node_device_attrs GROUP BY node_id")
	if err != nil {
		return nil, fmt.Errorf("state: counting device attributes: %w", err)
	}
	defer rows.Close()

	counts := make(map[NodeID]int)
	for rows.Next() {
		var (
			id    int64
			count int
		)
		if err := rows.Scan(&id, &count); err != nil {
			return nil, fmt.Errorf("state: scanning device attribute counts: %w", err)
		}
		counts[NodeID(id)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: counting device attributes: %w", err)
	}
	return counts, nil
}
