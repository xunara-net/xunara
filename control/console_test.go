package control

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

// TestConsoleRequiresSession checks that every console page sends anonymous
// browsers to the sign-in page with a return path.
func TestConsoleRequiresSession(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	for _, path := range []string{"/console/", "/console/machines", "/console/devices", "/console/audit"} {
		resp := getRequest(t, client, hs.URL+path, nil)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s status = %d, want 302", path, resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "/login?return_to=") || !strings.Contains(loc, url.QueryEscape(path)) {
			t.Fatalf("GET %s redirect = %q, want a login redirect for the same path", path, loc)
		}
	}
}

// TestConsolePagesRender walks every console page as a signed-in operator.
func TestConsolePagesRender(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	conn, _, _ := registerNode(t, s, hs, "console-node")
	defer conn.Close()

	pages := []struct {
		path string
		want string
	}{
		{"/console/", "machines online"},
		{"/console/machines", "console-node"},
		{"/console/devices", "No devices are waiting for approval."},
		{"/console/users", "Xunara User"},
		{"/console/dns", "No extra DNS records."},
		{"/console/auth-keys", "Create key"},
		{"/console/policy", "No policy document is configured"},
		{"/console/audit", identity.AuditNodeApproved},
	}

	for _, page := range pages {
		resp := getRequest(t, client, hs.URL+page.path, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", page.path, resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", page.path, cc)
		}
		if body := bodyString(t, resp); !strings.Contains(body, page.want) {
			t.Errorf("GET %s does not contain %q:\n%s", page.path, page.want, body)
		}
	}
}

// TestConsoleRejectsMissingCSRF checks that state-changing console POSTs
// require the session-bound form token.
func TestConsoleRejectsMissingCSRF(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	posts := []struct {
		path string
		form url.Values
	}{
		{"/console/auth-keys", url.Values{"ttl": {"1h"}}},
		{"/console/machines/1/delete", url.Values{}},
		{"/console/dns/1/delete", url.Values{}},
		{"/console/users/1", url.Values{"displayName": {"nope"}}},
	}
	for _, post := range posts {
		resp := postForm(t, client, hs.URL+post.path, post.form, cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without CSRF status = %d, want 403", post.path, resp.StatusCode)
		}
	}
	if keys := s.Store().ListPreAuthKeys(); len(keys) != 0 {
		t.Errorf("a CSRF-less POST created an auth key: %v", keys)
	}
}

// TestConsoleRouteApproval drives route approval through the console form.
func TestConsoleRouteApproval(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	conn, h2, nodeKey := registerNode(t, s, hs, "router")
	defer conn.Close()

	subnet := netip.MustParsePrefix("192.168.7.0/24")
	postRaw(t, h2, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: advertisedHostinfo("router", subnet),
	})

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found after map request")
	}
	if got := node.AnnouncedRoutes(); len(got) != 1 || got[0] != subnet {
		t.Fatalf("announced routes = %v, want [%s]", got, subnet)
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	csrf := extractCSRF(t, page)
	if !strings.Contains(page, subnet.String()) {
		t.Fatalf("machines page does not show the announced route %s", subnet)
	}

	action := fmt.Sprintf("/console/machines/%d/routes", node.ID)
	resp := postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"approve-all"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve-all status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "All announced routes approved.") {
		t.Errorf("approve-all page lacks the notice:\n%s", body)
	}

	node, ok = s.Store().GetNodeByID(node.ID)
	if !ok || !containsPrefix(node.ApprovedRoutes, subnet) {
		t.Fatalf("approved routes = %v, want [%s]", node.ApprovedRoutes, subnet)
	}
	if !auditActionSet(t, s)[identity.AuditRouteApproved] {
		t.Error("route approval was not audited")
	}

	// Withdrawing clears the approval again.
	resp = postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"unapprove-all"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapprove-all status = %d, want 200", resp.StatusCode)
	}
	node, _ = s.Store().GetNodeByID(node.ID)
	if len(node.ApprovedRoutes) != 0 {
		t.Fatalf("approved routes after withdraw = %v, want none", node.ApprovedRoutes)
	}
	if !auditActionSet(t, s)[identity.AuditRouteUnapproved] {
		t.Error("route withdrawal was not audited")
	}

	// An unknown action is refused, not treated as a no-op.
	resp = postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"nope"}}, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown action status = %d, want 400", resp.StatusCode)
	}
}

// TestConsoleMachineDelete removes a machine through the console.
func TestConsoleMachineDelete(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	conn, _, nodeKey := registerNode(t, s, hs, "doomed")
	defer conn.Close()

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found")
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	csrf := extractCSRF(t, page)
	action := fmt.Sprintf("/console/machines/%d/delete", node.ID)
	resp := postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "Machine doomed deleted.") {
		t.Errorf("delete page lacks the notice:\n%s", body)
	}
	if _, ok := s.Store().GetNodeByID(node.ID); ok {
		t.Error("machine still exists after console delete")
	}
	if !auditActionSet(t, s)[identity.AuditNodeDeleted] {
		t.Error("console delete was not audited")
	}
}

// TestConsoleAuthKeyLifecycle creates a key, checks the secret is only shown
// once, then revokes it.
func TestConsoleAuthKeyLifecycle(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/auth-keys")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/auth-keys", cookie))
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+"/console/auth-keys",
		url.Values{"csrf": {csrf}, "ttl": {"1h"}, "reusable": {"on"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want 200", resp.StatusCode)
	}

	keys := s.Store().ListPreAuthKeys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v, want one", keys)
	}
	key := keys[0]
	if !key.Reusable || key.UserID != state.DefaultUserID || key.Expiry.IsZero() {
		t.Errorf("key = %+v", key)
	}

	// The creation page shows the secret exactly once.
	if body := bodyString(t, resp); !strings.Contains(body, key.Key) {
		t.Errorf("creation page does not show the new secret:\n%s", body)
	}

	// Later reads must not.
	again := bodyString(t, getRequest(t, client, hs.URL+"/console/auth-keys", cookie))
	if strings.Contains(again, key.Key) {
		t.Error("the auth key secret is rendered after creation")
	}
	if !strings.Contains(again, fmt.Sprintf("<td>%d</td>", key.ID)) {
		t.Errorf("key list does not show key %d:\n%s", key.ID, again)
	}
	if !auditActionSet(t, s)[identity.AuditPreAuthKeyCreated] {
		t.Error("key creation was not audited")
	}

	resp = postForm(t, client, hs.URL+fmt.Sprintf("/console/auth-keys/%d/delete", key.ID),
		url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
	}
	if keys := s.Store().ListPreAuthKeys(); len(keys) != 0 {
		t.Errorf("keys after revoke = %v, want none", keys)
	}
	if !auditActionSet(t, s)[identity.AuditPreAuthKeyDeleted] {
		t.Error("key revocation was not audited")
	}
}

// TestConsoleDeviceApproval approves a pending device through the console.
func TestConsoleDeviceApproval(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/devices")

	conn, _, _, authID := startRegistration(t, hs, "console-device")
	defer conn.Close()

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/devices", cookie))
	if !strings.Contains(page, "console-device") {
		t.Fatalf("pending device list lacks the hostname:\n%s", page)
	}
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+"/console/devices/"+authID+"/approve", url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "Device approved.") {
		t.Errorf("approve page lacks the notice:\n%s", body)
	}

	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || da.State != identity.DeviceApproved {
		t.Fatalf("device authorization = %+v (ok=%v), want approved", da, ok)
	}
	if _, ok := s.Store().GetNodeByNodeKey(nodeKeyOfRegistration(t, s, authID)); !ok {
		t.Error("approving through the console did not create the node")
	}
	if da.UserID != state.DefaultUserID {
		t.Errorf("approved user = %d, want the signed-in user %d", da.UserID, state.DefaultUserID)
	}
}

// TestConsoleUserUpdate edits a user profile through the console.
func TestConsoleUserUpdate(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/users")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/users", cookie))
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+fmt.Sprintf("/console/users/%d", state.DefaultUserID),
		url.Values{"csrf": {csrf}, "displayName": {"Ops Team"}, "email": {"ops@example.com"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "User updated.") {
		t.Errorf("update page lacks the notice:\n%s", body)
	}

	user, ok := s.Identity().GetUser(state.DefaultUserID)
	if !ok || user.DisplayName != "Ops Team" || user.Email != "ops@example.com" {
		t.Fatalf("user = %+v (ok=%v)", user, ok)
	}
	if !auditActionSet(t, s)[identity.AuditUserUpdated] {
		t.Error("user update was not audited")
	}
}

// TestConsolePolicyPage shows the loaded policy document.
func TestConsolePolicyPage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	doc := `{
  // A policy with one rule and one unsupported field.
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
  "autoApprovers": {"routes": {"10.0.0.0/8": ["tag:router"]}},
}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}

	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/policy")

	resp := getRequest(t, client, hs.URL+"/console/policy", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy page status = %d, want 200", resp.StatusCode)
	}
	body := bodyString(t, resp)
	for _, want := range []string{"policy.hujson", "<dd>1</dd>", "Unsupported fields", "autoApprovers"} {
		if !strings.Contains(body, want) {
			t.Errorf("policy page lacks %q:\n%s", want, body)
		}
	}
}

// TestConsoleAuditNewestFirst checks the audit page shows recent events first.
func TestConsoleAuditNewestFirst(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/audit")

	if err := s.Store().CreatePreAuthKey(&state.PreAuthKey{Key: "tskey-auth-test", UserID: state.DefaultUserID}); err != nil {
		t.Fatalf("seeding key: %v", err)
	}
	s.audit("test", identity.AuditPreAuthKeyCreated, "preauthkey:1", "seeded")

	body := bodyString(t, getRequest(t, client, hs.URL+"/console/audit", cookie))
	if !strings.Contains(body, identity.AuditPreAuthKeyCreated) {
		t.Fatalf("audit page lacks the seeded event:\n%s", body)
	}
	if i, j := strings.Index(body, identity.AuditPreAuthKeyCreated), strings.Index(body, identity.AuditLoginSucceeded); i > j {
		t.Error("audit page is not newest-first")
	}
}
