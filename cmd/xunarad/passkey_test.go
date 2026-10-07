package main

import (
	"testing"
)

// TestBuildPasskeyConfigDerivesFromServerURL checks the implicit path: a
// deployment whose external URL can be a WebAuthn relying party gets passkey
// sign-in without extra configuration, and one whose URL cannot gets it
// disabled instead of a startup failure.
func TestBuildPasskeyConfigDerivesFromServerURL(t *testing.T) {
	cases := []struct {
		name       string
		serverURL  string
		wantRPID   string
		wantOrigin string
	}{
		{"https domain", "https://login.example.com", "login.example.com", "https://login.example.com"},
		{"https domain with port", "https://login.example.com:8443", "login.example.com", "https://login.example.com:8443"},
		{"loopback http", "http://localhost:8080", "localhost", "http://localhost:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := buildPasskeyConfig(true, tc.serverURL, "", "", nil)
			if err != nil {
				t.Fatalf("buildPasskeyConfig: %v", err)
			}
			if cfg == nil {
				t.Fatal("passkey sign-in was not derived from a usable server URL")
			}
			if cfg.RPID != tc.wantRPID || len(cfg.Origins) != 1 || cfg.Origins[0] != tc.wantOrigin {
				t.Fatalf("cfg = %+v, want RP ID %q origin %q", cfg, tc.wantRPID, tc.wantOrigin)
			}
		})
	}

	// URLs that cannot be a relying party disable the feature rather than
	// failing startup: plain http outside loopback, an IP address, a path,
	// and no URL at all.
	for _, serverURL := range []string{
		"http://login.example.com",
		"http://192.168.1.10:8080",
		"https://login.example.com/console",
		"",
	} {
		cfg, err := buildPasskeyConfig(true, serverURL, "", "", nil)
		if err != nil {
			t.Errorf("buildPasskeyConfig(%q): %v", serverURL, err)
		}
		if cfg != nil {
			t.Errorf("buildPasskeyConfig(%q) = %+v, want passkey sign-in disabled", serverURL, cfg)
		}
	}

	if cfg, err := buildPasskeyConfig(false, "https://login.example.com", "", "", nil); err != nil || cfg != nil {
		t.Errorf("buildPasskeyConfig(disabled) = %+v, %v, want nil, nil", cfg, err)
	}
}

// TestBuildPasskeyConfigExplicit checks the explicit path: an operator's
// configuration is either usable or a startup error, and the origin may be
// derived from -server-url when it belongs to the named RP ID.
func TestBuildPasskeyConfigExplicit(t *testing.T) {
	cfg, err := buildPasskeyConfig(true, "https://login.example.com", "example.com", "Xunara", nil)
	if err != nil {
		t.Fatalf("buildPasskeyConfig: %v", err)
	}
	if cfg.RPID != "example.com" || cfg.DisplayName != "Xunara" ||
		len(cfg.Origins) != 1 || cfg.Origins[0] != "https://login.example.com" {
		t.Fatalf("cfg = %+v, want the operator's RP ID and the derived origin", cfg)
	}

	explicit := []struct {
		name      string
		serverURL string
		rpID      string
		origins   []string
	}{
		{"RP ID without a usable origin", "http://192.168.1.10:8080", "example.com", nil},
		{"origins without an RP ID", "", "", []string{"https://login.example.com"}},
		{"origin outside the RP ID", "", "example.com", []string{"https://attacker.example"}},
		{"IP RP ID", "", "192.168.1.10", []string{"http://192.168.1.10:8080"}},
	}
	for _, tc := range explicit {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildPasskeyConfig(true, tc.serverURL, tc.rpID, "", tc.origins); err == nil {
				t.Fatal("buildPasskeyConfig accepted an unusable configuration")
			}
		})
	}
}

// TestHostUnderRPID covers the origin/RP ID relationship used by derivation.
func TestHostUnderRPID(t *testing.T) {
	cases := []struct {
		host, rpID string
		want       bool
	}{
		{"login.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"login.example.com", "login.example.com", true},
		{"example.com.evil.test", "example.com", false},
		{"badexample.com", "example.com", false},
		{"login.example.com.", "example.com", true},
	}
	for _, tc := range cases {
		if got := hostUnderRPID(tc.host, tc.rpID); got != tc.want {
			t.Errorf("hostUnderRPID(%q, %q) = %v, want %v", tc.host, tc.rpID, got, tc.want)
		}
	}
}
