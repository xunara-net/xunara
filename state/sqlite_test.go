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
