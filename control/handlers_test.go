package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleKeyGating(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	t.Run("supported version returns server key", func(t *testing.T) {
		if got := fetchControlKey(t, hs.URL); got != s.NoisePublicKey() {
			t.Errorf("advertised key = %v, want %v", got, s.NoisePublicKey())
		}
	})

	t.Run("missing version is rejected", func(t *testing.T) {
		resp, err := http.Get(hs.URL + "/key")
		if err != nil {
			t.Fatalf("GET /key: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("unsupported version does not leak the key", func(t *testing.T) {
		resp, err := http.Get(hs.URL + "/key?v=1")
		if err != nil {
			t.Fatalf("GET /key: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

func TestNoiseKeyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	first, err := New(Config{StateDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, err := New(Config{StateDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if first.NoisePublicKey() != second.NoisePublicKey() {
		t.Fatalf("noise key changed across restart: %v != %v",
			first.NoisePublicKey(), second.NoisePublicKey())
	}
}
