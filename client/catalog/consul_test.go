package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xunara/xunara/client/protocol"
)

// consulCatalog is a response with one entry per mapping rule, including
// everything that must be skipped.
const consulCatalog = `{
  "Bad_Name":   {"ID":"Bad_Name","Service":"Bad_Name","Port":80},
  "bigmeta":    {"ID":"bigmeta","Service":"bigmeta","Port":80,"Meta":{"a b":"secret-meta-value"}},
  "conflict-1": {"ID":"conflict-1","Service":"conflict","Port":80},
  "conflict-2": {"ID":"conflict-2","Service":"conflict","Port":81},
  "dns":        {"ID":"dns","Service":"dns","Tags":["udp"],"Port":53},
  "empty":      {"ID":"empty","Service":"","Port":80},
  "noport":     {"ID":"noport","Service":"noport","Port":0},
  "peer":       {"ID":"peer","Service":"remote","PeerName":"dc2","Port":9000},
  "proxy":      {"ID":"api-proxy","Service":"api-proxy","Kind":"connect-proxy","Port":21000},
  "socket":     {"ID":"dockerd","Service":"dockerd","SocketPath":"/var/run/docker.sock"},
  "v6":         {"ID":"v6","Service":"v6","Port":8080,"Ports":[{"Name":"http","Port":80,"Default":true},{"Name":"https","Port":443}]},
  "web-1":      {"ID":"web-1","Service":"web","Tags":["v1"],"Meta":{"version":"2"},"Port":8080},
  "web-2":      {"ID":"web-2","Service":"web","Tags":[],"Meta":{"version":"2"},"Port":8080}
}`

// TestConsulServicesMapping covers the mapping rules end to end against a fake
// agent: what is imported, what is skipped, and how the token is sent.
func TestConsulServicesMapping(t *testing.T) {
	var gotToken, gotQuery string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/agent/services" {
			http.NotFound(w, req)
			return
		}
		gotToken = req.Header.Get("X-Consul-Token")
		gotQuery = req.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(consulCatalog))
	}))
	defer hs.Close()

	// A bare host:port must work too, and the token must never reach the URL.
	address := strings.TrimPrefix(hs.URL, "http://")
	services, warnings, err := ConsulServices(context.Background(), ConsulConfig{
		Address: address,
		Token:   "consul-secret-token",
	})
	if err != nil {
		t.Fatalf("ConsulServices: %v", err)
	}
	if gotToken != "consul-secret-token" {
		t.Errorf("X-Consul-Token = %q, want the configured token", gotToken)
	}
	if gotQuery != "" || strings.Contains(address, "consul-secret-token") {
		t.Errorf("token leaked into the URL query %q", gotQuery)
	}

	want := []protocol.Service{
		{Name: "dns", Protocol: "udp", Port: 53},
		{Name: "v6", Protocol: "tcp", Port: 80},
		{Name: "web", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
	}
	if len(services) != len(want) {
		t.Fatalf("services = %+v, want %+v", services, want)
	}
	for i := range want {
		if services[i].Name != want[i].Name || services[i].Protocol != want[i].Protocol || services[i].Port != want[i].Port {
			t.Errorf("service[%d] = %+v, want %+v", i, services[i], want[i])
		}
	}
	if services[2].Metadata["version"] != "2" {
		t.Errorf("web metadata = %+v", services[2].Metadata)
	}

	if len(warnings) != 8 {
		t.Fatalf("warnings = %d (%v), want 8", len(warnings), warnings)
	}
	for _, want := range []string{"connect-proxy", "unix socket", "peer", "lowercase DNS label", "invalid port", "metadata key", "disagree on protocol/port", "no service name"} {
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning mentions %q: %v", want, warnings)
		}
	}
	if strings.Contains(strings.Join(warnings, " "), "secret-meta-value") {
		t.Errorf("warnings leaked a metadata value: %v", warnings)
	}
}

// TestConsulServicesErrors covers the failure paths: a rejected token, a
// malformed body, and a catalog that cannot be represented in full.
func TestConsulServicesErrors(t *testing.T) {
	status := http.StatusForbidden
	body := `{"errors":["Permission denied: token with AccessorID has insufficient permissions"]}`
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer hs.Close()

	_, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("403 error = %v", err)
	}

	status = http.StatusOK
	body = `not json`
	if _, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL}); err == nil {
		t.Error("a malformed catalog was accepted")
	}

	// More services than one node may publish: the import fails instead of
	// silently truncating (a truncated declaration would withdraw the rest).
	tooMany := map[string]consulAgentService{}
	for i := 0; i <= protocol.MaxServicesPerNode; i++ {
		name := fmt.Sprintf("svc-%02d", i)
		tooMany[name] = consulAgentService{ID: name, Service: name, Port: 80}
	}
	raw, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatalf("marshaling catalog: %v", err)
	}
	body = string(raw)
	if _, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("oversized catalog error = %v", err)
	}
}

// TestConsulServicesEmpty checks the empty catalog: no services, no warnings,
// and no error (the CLI warns before publishing an empty declaration).
func TestConsulServicesEmpty(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer hs.Close()

	services, warnings, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL})
	if err != nil {
		t.Fatalf("ConsulServices: %v", err)
	}
	if len(services) != 0 || len(warnings) != 0 {
		t.Errorf("services = %+v, warnings = %v", services, warnings)
	}
}
