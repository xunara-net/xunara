package main

import (
	"testing"
	"time"
)

// TestFluxConfigFor covers the opt-in rule: Flux stays off unless asked for,
// and settings without the switch are a startup error, not silently ignored.
func TestFluxConfigFor(t *testing.T) {
	if cfg, err := fluxConfigFor(false, "", 0, 0); err != nil || cfg != nil {
		t.Fatalf("disabled = %+v, %v; want nil, nil", cfg, err)
	}
	for _, tc := range []struct {
		name    string
		dir     string
		maxSize int64
		ttl     time.Duration
	}{
		{"dir", "/tmp/flux", 0, 0},
		{"size", "", 1 << 20, 0},
		{"ttl", "", 0, time.Hour},
	} {
		if cfg, err := fluxConfigFor(false, tc.dir, tc.maxSize, tc.ttl); err == nil || cfg != nil {
			t.Errorf("disabled with %s = %+v, %v; want an error naming the missing switch", tc.name, cfg, err)
		}
	}

	cfg, err := fluxConfigFor(true, "/tmp/flux", 1<<20, time.Hour)
	if err != nil {
		t.Fatalf("enabled: %v", err)
	}
	if cfg == nil || cfg.Disabled || cfg.Dir != "/tmp/flux" || cfg.MaxSize != 1<<20 || cfg.TTL != time.Hour {
		t.Fatalf("enabled = %+v", cfg)
	}
	if cfg, err := fluxConfigFor(true, "", 0, 0); err != nil || cfg == nil || cfg.Disabled {
		t.Fatalf("enabled with defaults = %+v, %v; want a non-nil enabled config", cfg, err)
	}
}
