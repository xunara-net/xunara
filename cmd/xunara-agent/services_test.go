package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara/xunara/client/daemon"
	"github.com/xunara/xunara/client/protocol"
)

// TestNormalizeServices checks the canonical form: protocol case and
// whitespace are folded, metadata is copied as-is.
func TestNormalizeServices(t *testing.T) {
	services, err := normalizeServices([]protocol.Service{
		{Name: "api", Protocol: " TCP ", Port: 8080, Metadata: map[string]string{"version": "1.2"}},
		{Name: "metrics", Protocol: "UDP", Port: 9090},
	})
	if err != nil {
		t.Fatalf("normalizeServices: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %+v", services)
	}
	if services[0].Protocol != "tcp" || services[1].Protocol != "udp" {
		t.Errorf("protocols = %q / %q, want lowercased", services[0].Protocol, services[1].Protocol)
	}
	if services[0].Metadata["version"] != "1.2" {
		t.Errorf("metadata = %+v", services[0].Metadata)
	}
}

// TestNormalizeServicesRejectsInvalid declares the rules the CLI mirrors from
// the server: one bad entry fails the whole declaration.
func TestNormalizeServicesRejectsInvalid(t *testing.T) {
	tooMany := make([]protocol.Service, maxServicesPerNode+1)
	for i := range tooMany {
		tooMany[i] = protocol.Service{Name: "svc", Protocol: "tcp", Port: 1}
	}

	tooMuchMetadata := map[string]string{}
	for i := 0; i < maxServiceMetadataEntries+1; i++ {
		tooMuchMetadata[string(rune('a'+i))] = "v"
	}

	cases := []struct {
		name     string
		services []protocol.Service
		want     string
	}{
		{"empty name", []protocol.Service{{Name: "", Protocol: "tcp", Port: 1}}, "empty"},
		{"uppercase name", []protocol.Service{{Name: "Api", Protocol: "tcp", Port: 1}}, "lowercase DNS label"},
		{"name too long", []protocol.Service{{Name: strings.Repeat("a", maxServiceNameLen+1), Protocol: "tcp", Port: 1}}, "longer than"},
		{"leading hyphen", []protocol.Service{{Name: "-api", Protocol: "tcp", Port: 1}}, "hyphen"},
		{"bad protocol", []protocol.Service{{Name: "api", Protocol: "sctp", Port: 1}}, "unsupported protocol"},
		{"zero port", []protocol.Service{{Name: "api", Protocol: "tcp", Port: 0}}, "invalid port"},
		{"port out of range", []protocol.Service{{Name: "api", Protocol: "tcp", Port: 65536}}, "invalid port"},
		{"duplicate name", []protocol.Service{
			{Name: "api", Protocol: "tcp", Port: 1},
			{Name: "api", Protocol: "udp", Port: 2},
		}, "listed twice"},
		{"too many services", tooMany, "at most"},
		{"metadata key with space", []protocol.Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: map[string]string{"a b": "v"}},
		}, "metadata key"},
		{"metadata control character", []protocol.Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: map[string]string{"k": "a\x1bb"}},
		}, "metadata value"},
		{"metadata too large", []protocol.Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: tooMuchMetadata},
		}, "more than"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeServices(tc.services)
			if err == nil {
				t.Fatal("normalizeServices accepted an invalid declaration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestReadServicesFile covers the file format: canonical declarations are
// accepted, typos are refused.
func TestReadServicesFile(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return path
	}

	path := write("ok.json", `{"services":[{"name":"api","protocol":"TCP","port":8080,"metadata":{"version":"1"}}]}`)
	services, err := readServicesFile(path)
	if err != nil {
		t.Fatalf("readServicesFile: %v", err)
	}
	if len(services) != 1 || services[0].Protocol != "tcp" || services[0].Metadata["version"] != "1" {
		t.Fatalf("services = %+v", services)
	}

	if _, err := readServicesFile(write("typo.json", `{"services":[{"name":"api","protcol":"tcp","port":1}]}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := readServicesFile(write("trailing.json", `{"services":[]} {}`)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("trailing data error = %v", err)
	}
	if _, err := readServicesFile(write("array.json", `[{"name":"api"}]`)); err == nil {
		t.Error("a bare array was accepted")
	}
	if _, err := readServicesFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// TestWriteServicesTable checks both renderings: a local declaration has no
// server fields, a stored set does.
func TestWriteServicesTable(t *testing.T) {
	var buf strings.Builder
	err := writeDeclaredServices(&buf, []protocol.Service{
		{Name: "web", Protocol: "tcp", Port: 80},
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"zone": "eu", "version": "2"}},
	})
	if err != nil {
		t.Fatalf("writeDeclaredServices: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NAME") || strings.Contains(out, "DNS NAME") {
		t.Errorf("declaration table has the wrong columns:\n%s", out)
	}
	if strings.Index(out, "api") > strings.Index(out, "web") {
		t.Errorf("declaration table is not sorted by name:\n%s", out)
	}
	if !strings.Contains(out, "api metadata:") || !strings.Contains(out, "zone") {
		t.Errorf("metadata is missing from the declaration table:\n%s", out)
	}

	buf.Reset()
	err = writePublishedServices(&buf, []protocol.ServiceView{
		{
			Name: "api", Protocol: "tcp", Port: 8080, DNSName: "api.example.com",
			Updated: time.Date(2026, 10, 8, 7, 0, 0, 0, time.UTC),
		},
		{Name: "web", Protocol: "tcp", Port: 80},
	})
	if err != nil {
		t.Fatalf("writePublishedServices: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "DNS NAME") || !strings.Contains(out, "api.example.com") {
		t.Errorf("stored table is missing the DNS name:\n%s", out)
	}
	var webLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "web") {
			webLine = line
		}
	}
	if strings.Count(webLine, "-") != 2 {
		t.Errorf("unknown server fields are not dashed out: %q", webLine)
	}

	buf.Reset()
	if err := writeDeclaredServices(&buf, nil); err != nil {
		t.Fatalf("writeDeclaredServices(nil): %v", err)
	}
	if !strings.Contains(buf.String(), "No services are declared") {
		t.Errorf("empty declaration output = %q", buf.String())
	}
}

// fakeServicesControl answers POST /api/agent/v1/services and records what it
// saw, so the CLI can be driven end to end without a control plane.
type fakeServicesControl struct {
	mu        sync.Mutex
	auth      string
	publishes [][]protocol.Service
	reject    map[string]bool
}

func (f *fakeServicesControl) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/api/agent/v1/services" {
		http.NotFound(w, req)
		return
	}
	var body struct {
		Services []protocol.Service `json:"services"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.auth = req.Header.Get("Authorization")
	f.publishes = append(f.publishes, body.Services)
	rejected := false
	for _, svc := range body.Services {
		if f.reject[svc.Name] {
			rejected = true
		}
	}
	f.mu.Unlock()

	if rejected {
		http.Error(w, "a service name is already in use", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"services": body.Services})
}

func (f *fakeServicesControl) state() (string, [][]protocol.Service) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]protocol.Service, len(f.publishes))
	copy(out, f.publishes)
	return f.auth, out
}

// TestServicesPublishListClear drives the CLI against a fake control plane:
// publish sends the declaration and saves it, a rejected publish leaves it
// alone, and clear withdraws it and removes the file.
func TestServicesPublishListClear(t *testing.T) {
	fake := &fakeServicesControl{reject: map[string]bool{"conflict": true}}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	machine, node := key.NewMachine(), key.NewNode()
	machineText, err := machine.MarshalText()
	if err != nil {
		t.Fatalf("machine marshaling: %v", err)
	}
	nodeText, err := node.MarshalText()
	if err != nil {
		t.Fatalf("node marshaling: %v", err)
	}
	if err := daemon.SaveState(stateDir, daemon.State{
		ServerURL:  hs.URL,
		MachineKey: string(machineText),
		NodeKey:    string(nodeText),
		Token:      "agent-token",
		NodeID:     7,
		StableID:   "n7",
	}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	dir := t.TempDir()
	declPath := filepath.Join(dir, "services.json")
	if err := os.WriteFile(declPath, []byte(`{"services":[{"name":"api","protocol":"tcp","port":8080}]}`), 0o600); err != nil {
		t.Fatalf("writing declaration: %v", err)
	}

	if err := runServicesPublish(context.Background(), []string{"-state-dir", stateDir, "-file", declPath}); err != nil {
		t.Fatalf("services publish: %v", err)
	}
	auth, publishes := fake.state()
	if auth != "Bearer agent-token" {
		t.Errorf("publish auth = %q, want the bearer token", auth)
	}
	if len(publishes) != 1 || len(publishes[0]) != 1 || publishes[0][0].Name != "api" || publishes[0][0].Port != 8080 {
		t.Fatalf("publishes = %+v", publishes)
	}
	declared, err := daemon.LoadServices(stateDir)
	if err != nil {
		t.Fatalf("LoadServices after publish: %v", err)
	}
	if len(declared) != 1 || declared[0].Name != "api" {
		t.Fatalf("saved declaration = %+v", declared)
	}

	if err := runServicesList([]string{"-state-dir", stateDir, "-json"}); err != nil {
		t.Fatalf("services list: %v", err)
	}

	// A rejected publish must not replace the working declaration.
	conflictPath := filepath.Join(dir, "conflict.json")
	if err := os.WriteFile(conflictPath, []byte(`{"services":[{"name":"conflict","protocol":"tcp","port":80}]}`), 0o600); err != nil {
		t.Fatalf("writing conflict declaration: %v", err)
	}
	if err := runServicesPublish(context.Background(), []string{"-state-dir", stateDir, "-file", conflictPath}); err == nil {
		t.Fatal("publish accepted a rejected declaration")
	}
	if declared, err := daemon.LoadServices(stateDir); err != nil || len(declared) != 1 || declared[0].Name != "api" {
		t.Errorf("declaration changed after a rejected publish: %+v (%v)", declared, err)
	}

	if err := runServicesClear(context.Background(), []string{"-state-dir", stateDir}); err != nil {
		t.Fatalf("services clear: %v", err)
	}
	_, publishes = fake.state()
	if len(publishes) != 3 || len(publishes[2]) != 0 {
		t.Fatalf("publishes after clear = %+v, want a final empty set", publishes)
	}
	if _, err := daemon.LoadServices(stateDir); !os.IsNotExist(err) {
		t.Errorf("declaration file survived clear: %v", err)
	}
}
