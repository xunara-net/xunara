package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// platformJSONRequest performs one platform API request with an optional JSON
// body, addressed to an explicit Host.
func platformJSONRequest(t *testing.T, hs *httptest.Server, method, host, path, token string, body any) *http.Response {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshalling the request: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, hs.URL+path, reader)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// newManagedOrgRouter builds a router hosting one configured organization plus
// a platform registry rooted at dir.
func newManagedOrgRouter(t *testing.T, dir string) (*Router, *httptest.Server) {
	t.Helper()

	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	registry := newTestRegistry(t, dir)
	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: "platform-secret",
		Registry:           registry,
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)
	return router, hs
}

// globexCreateBody is a valid managed-organization request.
func globexCreateBody() map[string]any {
	return map[string]any{
		"id":         "globex",
		"name":       "Globex",
		"domains":    []string{"Login.Globex.Example.com"},
		"server_url": "https://login.globex.example.com",
		"domain":     "globex.example.com",
	}
}

// TestPlatformOrganizationLifecycle drives the full CRUD flow through HTTP and
// checks that routing follows.
func TestPlatformOrganizationLifecycle(t *testing.T) {
	router, hs := newManagedOrgRouter(t, t.TempDir())
	const token = "platform-secret"
	staticKey := fetchKeyAtHost(t, hs, "login.acme.example.com")

	// Create.
	resp := platformJSONRequest(t, hs, http.MethodPost, "login.acme.example.com",
		"/api/platform/v1/organizations", token, globexCreateBody())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	var created PlatformOrg
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decoding the created organization: %v", err)
	}
	if created.ID != "globex" || !created.Managed || len(created.Domains) != 1 ||
		created.Domains[0] != "login.globex.example.com" {
		t.Fatalf("created organization = %+v", created)
	}

	// The new host is served by a control plane of its own.
	managedKey := fetchKeyAtHost(t, hs, "login.globex.example.com")
	if managedKey == staticKey {
		t.Error("the managed organization reuses the configured organization's Noise key")
	}

	// Read: both organizations, with the source marked.
	resp = platformJSONRequest(t, hs, http.MethodGet, "login.acme.example.com",
		"/api/platform/v1/organizations", token, nil)
	var list struct {
		Organizations []PlatformOrg `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	if len(list.Organizations) != 2 || list.Organizations[0].ID != "acme" || list.Organizations[0].Managed {
		t.Errorf("configured organization view = %+v", list.Organizations)
	}
	if got := list.Organizations[1]; got.ID != "globex" || !got.Managed {
		t.Errorf("managed organization view = %+v", got)
	}
	resp = platformJSONRequest(t, hs, http.MethodGet, "login.acme.example.com",
		"/api/platform/v1/organizations/globex", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d, want 200", resp.StatusCode)
	}

	// Update: rename and retarget the domains. The new set keeps the URL host
	// routable but adds the apex and drops the wildcard.
	resp = platformJSONRequest(t, hs, http.MethodPatch, "login.acme.example.com",
		"/api/platform/v1/organizations/globex", token,
		map[string]any{"name": "Globex Inc", "domains": []string{"login.globex.example.com", "globex.example.com"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch status = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	var patched PlatformOrg
	if err := json.NewDecoder(resp.Body).Decode(&patched); err != nil {
		t.Fatalf("decoding the patched organization: %v", err)
	}
	if patched.Name != "Globex Inc" || len(patched.Domains) != 2 {
		t.Fatalf("patched organization = %+v", patched)
	}
	fetchKeyAtHost(t, hs, "globex.example.com")
	if resp := requestAtHost(t, hs, "node.globex.example.com", "/key?v=115"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("wildcard host status = %d, want 404 after retargeting", resp.StatusCode)
	}

	// Delete: routing stops, the state directory is archived, the row is gone.
	resp = platformJSONRequest(t, hs, http.MethodDelete, "login.acme.example.com",
		"/api/platform/v1/organizations/globex", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	var deleted struct {
		Deleted    bool   `json:"deleted"`
		ArchivedAt string `json:"archivedAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&deleted); err != nil {
		t.Fatalf("decoding the delete response: %v", err)
	}
	if !deleted.Deleted || !strings.Contains(deleted.ArchivedAt, "deleted") {
		t.Errorf("delete response = %+v", deleted)
	}
	if resp := requestAtHost(t, hs, "node.globex.example.com", "/key?v=115"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted host status = %d, want 404", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodDelete, "login.acme.example.com",
		"/api/platform/v1/organizations/globex", token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", resp.StatusCode)
	}
	if got := len(router.orgSnapshot()); got != 1 {
		t.Errorf("served organizations = %d, want only the configured one", got)
	}
}

// TestPlatformOrganizationRejections pins the validation and conflict paths.
func TestPlatformOrganizationRejections(t *testing.T) {
	_, hs := newManagedOrgRouter(t, t.TempDir())
	const token = "platform-secret"
	base := "login.acme.example.com"

	body := func(mutate func(map[string]any)) map[string]any {
		req := globexCreateBody()
		mutate(req)
		return req
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"duplicate id", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) {
				m["id"] = "acme"
				m["domains"] = []string{"other.example.com"}
				m["server_url"] = "https://other.example.com"
			}), http.StatusConflict},
		{"duplicate domain", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) {
				m["domains"] = []string{"login.acme.example.com"}
				m["server_url"] = "https://login.acme.example.com"
			}), http.StatusConflict},
		{"bad id", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) { m["id"] = "../etc" }), http.StatusBadRequest},
		{"no domains", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) { m["domains"] = []string{} }), http.StatusBadRequest},
		{"url outside the domains", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) { m["server_url"] = "https://login.other.example.com" }), http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/platform/v1/organizations",
			body(func(m map[string]any) { m["state_dir"] = "/etc" }), http.StatusBadRequest},
		{"patch configured organization", http.MethodPatch, "/api/platform/v1/organizations/acme",
			map[string]any{"name": "Nope"}, http.StatusConflict},
		{"patch unknown organization", http.MethodPatch, "/api/platform/v1/organizations/nobody",
			map[string]any{"name": "Nope"}, http.StatusNotFound},
		{"patch without changes", http.MethodPatch, "/api/platform/v1/organizations/acme",
			map[string]any{}, http.StatusBadRequest},
		{"delete configured organization", http.MethodDelete, "/api/platform/v1/organizations/acme",
			nil, http.StatusConflict},
		{"delete unknown organization", http.MethodDelete, "/api/platform/v1/organizations/nobody",
			nil, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := platformJSONRequest(t, hs, tc.method, base, tc.path, token, tc.body)
			// A read-only conflict for a configured organization may surface
			// before or after body validation; both are client errors.
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d (%s), want %d", resp.StatusCode, bodyString(t, resp), tc.want)
			}
		})
	}

	// Without a registry the CRUD is disabled, not silently ignored.
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	plain := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: token,
	})
	plainHS := httptest.NewServer(plain.Handler())
	t.Cleanup(plainHS.Close)
	resp := platformJSONRequest(t, plainHS, http.MethodPost, base, "/api/platform/v1/organizations", token, globexCreateBody())
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("create without a registry status = %d, want 403", resp.StatusCode)
	}
	resp = platformJSONRequest(t, plainHS, http.MethodDelete, base, "/api/platform/v1/organizations/globex", token, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete without a registry status = %d, want 403", resp.StatusCode)
	}
}

// TestPlatformManagedOrganizationSurvivesRestart checks that a managed
// organization is rebuilt from its state directory with the same identity.
func TestPlatformManagedOrganizationSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	const token = "platform-secret"

	first, hs := newManagedOrgRouter(t, dir)
	resp := platformJSONRequest(t, hs, http.MethodPost, "login.acme.example.com",
		"/api/platform/v1/organizations", token, globexCreateBody())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	before := fetchKeyAtHost(t, hs, "login.globex.example.com")
	if err := first.Close(); err != nil {
		t.Fatalf("closing the first router: %v", err)
	}

	// A fresh process: reopen the same registry and serve again.
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	registry := newTestRegistry(t, dir)
	second := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: token,
		Registry:           registry,
	})
	hs2 := httptest.NewServer(second.Handler())
	t.Cleanup(hs2.Close)

	if after := fetchKeyAtHost(t, hs2, "login.globex.example.com"); after != before {
		t.Error("the managed organization lost its Noise key across a restart")
	}
}
