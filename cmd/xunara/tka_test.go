package main

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// TestReadTKAHead covers the read-only chain lookup: a missing store, an empty
// store and a store holding a genesis chain.
func TestReadTKAHead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tka")

	if head, err := readTKAHead(dir); err != nil || head != "" {
		t.Fatalf("head of a missing store = %q, %v; want empty without an error", head, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if head, err := readTKAHead(dir); err != nil || head != "" {
		t.Fatalf("head of an empty store = %q, %v; want empty without an error", head, err)
	}

	// A real chain, the way `tailscale lock init` creates one.
	priv := key.NewNLPrivate()
	chonk, err := tka.ChonkDir(dir)
	if err != nil {
		t.Fatalf("ChonkDir: %v", err)
	}
	k := tka.Key{Kind: tka.Key25519, Public: priv.Public().Verifier(), Votes: 1}
	_, genesis, err := tka.Create(chonk, tka.CreateStateForTest(k), priv)
	if err != nil {
		t.Fatalf("tka.Create: %v", err)
	}

	head, err := readTKAHead(dir)
	if err != nil {
		t.Fatalf("readTKAHead: %v", err)
	}
	if head != genesis.Hash().String() {
		t.Errorf("head = %q, want %q", head, genesis.Hash().String())
	}
}
