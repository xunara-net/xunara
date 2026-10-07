package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// openTestSQLite opens a SQLite store in a temporary directory.
func openTestSQLite(t *testing.T, path string) *SQLiteStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteStoreConformance(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLitePreAuthKeyConformance(t *testing.T) {
	runPreAuthKeyConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLiteDNSRecordConformance(t *testing.T) {
	runDNSRecordConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLiteTKAConformance(t *testing.T) {
	runTKAConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

// TestSQLiteTKAMetaPersistsAcrossReopen checks the tailnet-lock bookkeeping
// survives a restart, which multi-instance failover depends on.
func TestSQLiteTKAMetaPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	first, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	want := TKAMeta{EverEnabled: true, Enabled: true, DisablementSecretSealed: "v1:sealed"}
	if err := first.SetTKAMeta(want); err != nil {
		t.Fatalf("SetTKAMeta: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { second.Close() })
	if got := second.TKAMeta(); got != want {
		t.Errorf("TKAMeta after reopen = %+v, want %+v", got, want)
	}
}

// TestSQLitePreAuthKeyPersistsAcrossReopen checks keys survive a restart and
// that the ID counter does not restart with them.
func TestSQLitePreAuthKeyPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()

	first, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	k := PreAuthKey{Key: "tskey-auth-durable", Reusable: true}
	if err := first.CreatePreAuthKey(&k); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, ok := second.GetPreAuthKey(k.Key)
	if !ok {
		t.Fatal("pre-auth key did not survive reopen")
	}
	if got.ID != k.ID || !got.Reusable {
		t.Errorf("key changed across reopen: %+v", got)
	}

	next := PreAuthKey{Key: "tskey-auth-next"}
	if err := second.CreatePreAuthKey(&next); err != nil {
		t.Fatalf("CreatePreAuthKey after reopen: %v", err)
	}
	if next.ID == k.ID {
		t.Error("pre-auth key ID counter restarted after reopen")
	}
}

// TestSQLiteStorePersistsAcrossReopen is the point of a durable store: node
// identity must survive a server restart, including the Noise-adjacent key
// material the Compatibility Core binds to.
func TestSQLiteStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}

	n := Node{Hostname: "durable", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive reopen")
	}
	if got.ID != n.ID || got.StableID != n.StableID {
		t.Errorf("identity changed: got id=%d stable=%q, want id=%d stable=%q",
			got.ID, got.StableID, n.ID, n.StableID)
	}
	if got.IPv4 != n.IPv4 || got.IPv6 != n.IPv6 {
		t.Errorf("addresses changed: got %v/%v, want %v/%v", got.IPv4, got.IPv6, n.IPv4, n.IPv6)
	}

	// A node created after reopen must not collide with the existing one.
	next := Node{Hostname: "next", NodeKey: key.NewNode().Public()}
	if err := second.CreateNode(&next); err != nil {
		t.Fatalf("CreateNode after reopen: %v", err)
	}
	if next.ID == n.ID {
		t.Error("ID counter restarted after reopen")
	}
	if next.IPv4 == n.IPv4 {
		t.Error("IPv4 counter restarted after reopen")
	}
}

// TestSQLiteMigratesV7ToV8 simulates a database written before the node's
// network-lock key was persisted: reopening it must apply the v8 migration
// instead of failing on the missing column.
func TestSQLiteMigratesV7ToV8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	n := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "ALTER TABLE nodes DROP COLUMN nl_key"); err != nil {
		t.Fatalf("dropping nl_key: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "PRAGMA user_version = 7"); err != nil {
		t.Fatalf("downgrading schema version: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive the v7 -> v8 migration")
	}
	if !got.NLKey.IsZero() {
		t.Errorf("NLKey = %v, want the zero value for a pre-v8 node", got.NLKey)
	}

	got.NLKey = key.NewNLPrivate().Public()
	if err := second.UpdateNode(got); err != nil {
		t.Fatalf("UpdateNode after migration: %v", err)
	}
	again, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node disappeared after update")
	}
	if again.NLKey != got.NLKey {
		t.Errorf("NLKey after migration = %v, want %v", again.NLKey, got.NLKey)
	}
}

func TestSQLiteStoreConcurrentAccess(t *testing.T) {
	s := openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 16 {
			n := Node{NodeKey: key.NewNode().Public()}
			if err := s.CreateNode(&n); err != nil {
				t.Errorf("CreateNode: %v", err)
				return
			}
		}
	}()

	for range 16 {
		_ = s.ListNodes()
	}
	<-done

	if got := len(s.ListNodes()); got != 16 {
		t.Errorf("ListNodes len = %d, want 16", got)
	}
}
