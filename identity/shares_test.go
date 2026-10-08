package identity

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// TestEnsureShareUser checks the synthetic user namespace: stable per key,
// distinct per organization, and above the reserved base.
func TestEnsureShareUser(t *testing.T) {
	s := openTestStore(t)

	id, err := s.EnsureShareUser("acme", "user:7")
	if err != nil {
		t.Fatalf("EnsureShareUser: %v", err)
	}
	if id < ShareUserIDBase {
		t.Errorf("synthetic user ID = %d, want >= %d", id, ShareUserIDBase)
	}
	again, err := s.EnsureShareUser("acme", "user:7")
	if err != nil || again != id {
		t.Errorf("EnsureShareUser repeat = %d (%v), want %d", again, err, id)
	}
	other, err := s.EnsureShareUser("acme", "user:8")
	if err != nil || other == id {
		t.Errorf("EnsureShareUser(other key) = %d (%v), want a fresh ID", other, err)
	}
	foreign, err := s.EnsureShareUser("globex", "user:7")
	if err != nil || foreign == id {
		t.Errorf("EnsureShareUser(other org) = %d (%v), want a fresh ID", foreign, err)
	}
	if got, ok := s.ShareUser("acme", "user:7"); !ok || got != id {
		t.Errorf("ShareUser = %d, %v, want %d, true", got, ok, id)
	}
	if _, ok := s.ShareUser("acme", "missing"); ok {
		t.Error("ShareUser returned an unknown key")
	}
}

// TestEnsureShareUserPersists checks the durable allocator keeps both the
// mapping and the counter across a reopen.
func TestEnsureShareUserPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")

	first, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	first.SetMaxOpenConns(1)
	firstStore, err := NewSQLiteStore(context.Background(), first)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	want, err := firstStore.EnsureShareUser("acme", "user:7")
	if err != nil {
		t.Fatalf("EnsureShareUser: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("reopen sql.Open: %v", err)
	}
	second.SetMaxOpenConns(1)
	t.Cleanup(func() { second.Close() })
	secondStore, err := NewSQLiteStore(context.Background(), second)
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore: %v", err)
	}

	got, err := secondStore.EnsureShareUser("acme", "user:7")
	if err != nil {
		t.Fatalf("EnsureShareUser after reopen: %v", err)
	}
	if got != want {
		t.Errorf("synthetic user ID after reopen = %d, want %d", got, want)
	}
	fresh, err := secondStore.EnsureShareUser("acme", "user:8")
	if err != nil || fresh == want {
		t.Errorf("fresh allocation after reopen = %d (%v), want a new ID", fresh, err)
	}
}
