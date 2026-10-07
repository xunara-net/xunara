package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeOrgConfig writes a config file into a temp dir and returns its path.
func writeOrgConfig(t *testing.T, doc string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "orgs.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing org config: %v", err)
	}
	return path
}

// TestLoadOrgSitesHostsEachOrganization builds one server per row and checks
// the isolation-critical fields (distinct state directories, distinct keys).
func TestLoadOrgSitesHostsEachOrganization(t *testing.T) {
	base := t.TempDir()
	path := writeOrgConfig(t, `{
		"organizations": [
			{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
			 "server_url": "https://login.acme.example.com",
			 "state_dir": "`+base+`/acme", "domain": "acme.example.com",
			 "node_key_expiry": "180d", "nameservers": ["1.1.1.1"]},
			{"id": "globex", "name": "Globex", "domains": ["*.globex.example.com"],
			 "server_url": "https://login.globex.example.com",
			 "state_dir": "`+base+`/globex", "domain": "globex.example.com"}
		]
	}`)

	sites, err := loadOrgSites(path, slog.Default())
	if err != nil {
		t.Fatalf("loadOrgSites: %v", err)
	}
	defer func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}()

	if len(sites) != 2 {
		t.Fatalf("sites = %d, want 2", len(sites))
	}
	if sites[0].ID != "acme" || sites[0].Name != "Acme" || sites[1].ID != "globex" {
		t.Errorf("site metadata = %+v / %+v", sites[0], sites[1])
	}
	if sites[0].Server.NoisePublicKey() == sites[1].Server.NoisePublicKey() {
		t.Error("organizations share a Noise key; each state directory must own its key")
	}
}

// TestLoadOrgSitesRejectsBrokenTables pins the fail-closed validation.
func TestLoadOrgSitesRejectsBrokenTables(t *testing.T) {
	base := t.TempDir()
	dir := func(name string) string { return filepath.Join(base, name) }

	valid := `{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
		"server_url": "https://login.acme.example.com", "state_dir": "%s", "domain": "acme.example.com"}`

	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"empty list", `{"organizations": []}`, "no organizations"},
		{"unknown field", `{"organizations": [` + sprintf(valid, dir("a")) + `], "extra": 1}`, "unknown field"},
		{"missing id", `{"organizations": [{"name": "x", "server_url": "https://x.example.com", "state_dir": "` + dir("b") + `"}]}`, "id is required"},
		{"missing server url", `{"organizations": [{"id": "a", "state_dir": "` + dir("c") + `"}]}`, "server_url is required"},
		{"missing state dir", `{"organizations": [{"id": "a", "server_url": "https://a.example.com"}]}`, "state_dir is required"},
		{"shared state dir", `{"organizations": [` + sprintf(valid, dir("d")) + `, {"id": "b", "server_url": "https://b.example.com", "state_dir": "` + dir("d") + `"}]}`, "already used"},
		{"bad expiry", `{"organizations": [` + strings.Replace(sprintf(valid, dir("e")), `"id": "acme"`, `"id": "acme", "node_key_expiry": "180x"`, 1) + `]}`, "node_key_expiry"},
		{"bad derp map", `{"organizations": [` + strings.Replace(sprintf(valid, dir("f")), `"id": "acme"`, `"id": "acme", "derp_map": "`+dir("missing.json")+`"`, 1) + `]}`, "no such file"},
		{"derp policy without a map", `{"organizations": [` + strings.Replace(sprintf(valid, dir("g")), `"id": "acme"`, `"id": "acme", "derp_policy": {"mode": "regions", "regions": [900]}`, 1) + `]}`, "needs a configured DERP map"},
		{"derp policy unknown region", `{"organizations": [` + strings.Replace(sprintf(valid, dir("h")), `"id": "acme"`, `"id": "acme", "derp_map": "`+writeDERPMapFile(t, 900)+`", "derp_policy": {"mode": "regions", "regions": [7]}`, 1) + `]}`, "not in the configured DERP map"},
		{"derp regions without the mode", `{"organizations": [` + strings.Replace(sprintf(valid, dir("i")), `"id": "acme"`, `"id": "acme", "derp_policy": {"mode": "none", "regions": [900]}`, 1) + `]}`, "only meaningful with policy mode"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeOrgConfig(t, tc.doc)
			sites, err := loadOrgSites(path, slog.Default())
			for _, site := range sites {
				_ = site.Server.Close()
			}
			if err == nil {
				t.Fatal("loadOrgSites accepted an invalid table")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// writeDERPMapFile writes a minimal tailcfg.DERPMap JSON document holding the
// given region IDs and returns its path.
func writeDERPMapFile(t *testing.T, regionIDs ...int) string {
	t.Helper()

	regions := make([]string, 0, len(regionIDs))
	for _, id := range regionIDs {
		regions = append(regions, fmt.Sprintf(
			`"%d": {"RegionID": %d, "RegionCode": "r%d", "Nodes": [{"Name": "r%da", "RegionID": %d, "HostName": "derp.example.com"}]}`,
			id, id, id, id, id))
	}
	doc := `{"Regions": {` + strings.Join(regions, ",") + `}}`

	path := filepath.Join(t.TempDir(), "derp.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing DERP map: %v", err)
	}
	return path
}

// TestLoadOrgSitesDERPPolicy checks the policy travels from the organization
// table into the per-organization server, filtered against its DERP map.
func TestLoadOrgSitesDERPPolicy(t *testing.T) {
	base := t.TempDir()
	derpMap := writeDERPMapFile(t, 900, 901)
	path := writeOrgConfig(t, `{
		"organizations": [
			{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
			 "server_url": "https://login.acme.example.com",
			 "state_dir": "`+base+`/acme", "domain": "acme.example.com",
			 "derp_map": "`+derpMap+`",
			 "derp_policy": {"mode": "regions", "regions": [900]}}
		]
	}`)

	sites, err := loadOrgSites(path, slog.Default())
	if err != nil {
		t.Fatalf("loadOrgSites: %v", err)
	}
	defer func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}()

	served := sites[0].Server.DERPMap()
	if served == nil || len(served.Regions) != 1 {
		t.Fatalf("served DERP map = %+v, want only region 900", served)
	}
	if served.Regions[900] == nil {
		t.Error("region 900 is missing from the served map")
	}
	if _, ok := served.Regions[901]; ok {
		t.Error("region 901 was filtered out of the map but is still served")
	}
}

// TestParseNodeKeyExpiry covers the day-suffix extension.
func TestParseNodeKeyExpiry(t *testing.T) {
	cases := map[string]time.Duration{
		"":      0,
		"180d":  180 * 24 * time.Hour,
		"4320h": 180 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseNodeKeyExpiry(in)
		if err != nil {
			t.Fatalf("parseNodeKeyExpiry(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseNodeKeyExpiry(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"180x", "d", "-1d"} {
		if _, err := parseNodeKeyExpiry(bad); err == nil {
			t.Errorf("parseNodeKeyExpiry(%q) accepted an invalid value", bad)
		}
	}
}

// TestCheckOrgScopedFlags keeps the ambiguity guard honest.
func TestCheckOrgScopedFlags(t *testing.T) {
	if err := checkOrgScopedFlags([]string{"listen", "log-level"}); err != nil {
		t.Errorf("process-level flags rejected: %v", err)
	}
	err := checkOrgScopedFlags([]string{"state-dir", "policy"})
	if err == nil {
		t.Fatal("org-scoped flags accepted in -org-config mode")
	}
	if !strings.Contains(err.Error(), "-state-dir") || !strings.Contains(err.Error(), "-policy") {
		t.Errorf("error = %v, want both offending flags named", err)
	}
}

// sprintf keeps the table literals readable.
func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
