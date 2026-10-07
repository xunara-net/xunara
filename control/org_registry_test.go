package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newTestRegistry opens a registry whose factory builds real control planes in
// a temp directory, plus the config paths needed to reopen it.
func newTestRegistry(t *testing.T, dir string) *OrgRegistry {
	t.Helper()

	registry, err := OpenOrgRegistry(context.Background(), OrgRegistryConfig{
		Path:      filepath.Join(dir, "platform.db"),
		StateRoot: filepath.Join(dir, "orgs"),
		NewServer: func(org ManagedOrg, stateDir string) (*Server, error) {
			return New(Config{ServerURL: org.ServerURL, Domain: org.Domain, StateDir: stateDir})
		},
	})
	if err != nil {
		t.Fatalf("OpenOrgRegistry: %v", err)
	}
	return registry
}

// testManagedOrg is a valid specification for the tests below.
func testManagedOrg() ManagedOrg {
	return ManagedOrg{
		ID:        "acme",
		Name:      "Acme",
		Domains:   []string{"Login.Acme.Example.com"},
		ServerURL: "https://login.acme.example.com",
		Domain:    "acme.example.com",
	}
}

func TestOrgRegistryCRUD(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	registry := newTestRegistry(t, dir)

	created, err := registry.Create(ctx, testManagedOrg())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("Create did not assign timestamps")
	}
	if created.Domains[0] != "Login.Acme.Example.com" {
		t.Errorf("Create rewrote the stored domains: %v", created.Domains)
	}

	if _, err := registry.Create(ctx, testManagedOrg()); !errors.Is(err, ErrOrgExists) {
		t.Fatalf("duplicate Create = %v, want ErrOrgExists", err)
	}

	got, ok, err := registry.Get(ctx, "acme")
	if err != nil || !ok {
		t.Fatalf("Get = %+v, %v, %v; want the created organization", got, ok, err)
	}
	if got.Name != "Acme" || got.ServerURL != "https://login.acme.example.com" {
		t.Errorf("Get = %+v", got)
	}
	if list, err := registry.List(ctx); err != nil || len(list) != 1 || list[0].ID != "acme" {
		t.Errorf("List = %+v, %v; want just acme", list, err)
	}

	updated := got
	updated.Name = "Acme Renamed"
	updated.Domains = []string{"*.acme.example.com"}
	stored, err := registry.Update(ctx, updated)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if stored.Name != "Acme Renamed" || len(stored.Domains) != 1 || stored.Domains[0] != "*.acme.example.com" {
		t.Errorf("Update = %+v", stored)
	}
	if !stored.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("Update changed created_at: %v -> %v", created.CreatedAt, stored.CreatedAt)
	}
	if _, err := registry.Update(ctx, ManagedOrg{ID: "globex", Name: "Globex", Domains: []string{"globex.example.com"}, ServerURL: "https://globex.example.com"}); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("update unknown = %v, want ErrOrgNotFound", err)
	}

	if err := registry.Delete(ctx, "acme"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := registry.Delete(ctx, "acme"); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("second Delete = %v, want ErrOrgNotFound", err)
	}
	if _, ok, _ := registry.Get(ctx, "acme"); ok {
		t.Error("organization still present after Delete")
	}

	// The registry is durable: reopening it shows the same (now empty) state
	// and accepts new rows.
	if err := registry.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened := newTestRegistry(t, dir)
	defer reopened.Close()
	if list, err := reopened.List(ctx); err != nil || len(list) != 0 {
		t.Errorf("reopened List = %+v, %v; want empty", list, err)
	}
	if _, err := reopened.Create(ctx, testManagedOrg()); err != nil {
		t.Errorf("Create after reopen: %v", err)
	}
}

func TestOrgRegistryValidation(t *testing.T) {
	registry := newTestRegistry(t, t.TempDir())
	registry.Close()

	base := testManagedOrg()
	for name, mutate := range map[string]func(*ManagedOrg){
		"bad id":                  func(o *ManagedOrg) { o.ID = "Acme/../etc" },
		"uppercase id":            func(o *ManagedOrg) { o.ID = "Acme" },
		"empty name":              func(o *ManagedOrg) { o.Name = "  " },
		"no domains":              func(o *ManagedOrg) { o.Domains = nil },
		"duplicate domains":       func(o *ManagedOrg) { o.Domains = []string{"a.example.com", "A.example.com."} },
		"bare host":               func(o *ManagedOrg) { o.Domains = []string{"example"} },
		"wildcard magic dns":      func(o *ManagedOrg) { o.Domain = "*.acme.example.com" },
		"missing scheme":          func(o *ManagedOrg) { o.ServerURL = "login.acme.example.com" },
		"url with credentials":    func(o *ManagedOrg) { o.ServerURL = "https://user:pass@login.acme.example.com" },
		"url outside the domains": func(o *ManagedOrg) { o.ServerURL = "https://login.other.example.com" },
		"url with a query":        func(o *ManagedOrg) { o.ServerURL = "https://login.acme.example.com/?tenant=1" },
	} {
		t.Run(name, func(t *testing.T) {
			org := base
			mutate(&org)
			if err := validateManagedOrg(org); err == nil {
				t.Fatal("validateManagedOrg accepted an invalid organization")
			}
		})
	}

	// A wildcard routing domain is fine, and the server URL may point at a
	// host inside it.
	ok := base
	ok.ID = "globex"
	ok.Domains = []string{"*.globex.example.com"}
	ok.ServerURL = "https://login.globex.example.com"
	if err := validateManagedOrg(ok); err != nil {
		t.Errorf("validateManagedOrg rejected a valid organization: %v", err)
	}
}

func TestOrgRegistryArchiveState(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	registry := newTestRegistry(t, dir)
	defer registry.Close()

	org, err := registry.Create(ctx, testManagedOrg())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	server, err := registry.NewServer(org)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	stateDir := registry.StateDir("acme")
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("state directory was not created: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("closing the organization: %v", err)
	}

	archived, err := registry.ArchiveState("acme")
	if err != nil {
		t.Fatalf("ArchiveState: %v", err)
	}
	if archived == "" {
		t.Fatal("ArchiveState returned no path")
	}
	if _, err := os.Stat(archived); err != nil {
		t.Errorf("archived directory is missing: %v", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state directory still exists after archiving: %v", err)
	}
	if name := filepath.Base(archived); name == "acme" {
		t.Errorf("archive kept the original name %q", name)
	}

	// Archiving a directory that does not exist is not an error: the caller
	// may have deleted the organization before its server ever started.
	if path, err := registry.ArchiveState("acme"); err != nil || path != "" {
		t.Errorf("second ArchiveState = %q, %v; want an empty no-op", path, err)
	}
}
