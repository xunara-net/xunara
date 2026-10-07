package protocol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

// fakeControl answers the agent endpoints and records what it saw.
type fakeControl struct {
	requests []recordedRequest

	enrollStatus int
	enrollBody   EnrollResponse

	netmapStatus int
	netmapBody   string

	heartbeatStatus int

	servicesStatus int
	servicesBody   string
}

type recordedRequest struct {
	path        string
	auth        string
	userAgent   string
	contentType string
	raw         []byte
}

func (f *fakeControl) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, recordedRequest{
		path:        req.URL.Path,
		auth:        req.Header.Get("Authorization"),
		userAgent:   req.Header.Get("User-Agent"),
		contentType: req.Header.Get("Content-Type"),
		raw:         raw,
	})

	switch req.URL.Path {
	case "/api/agent/v1/enroll":
		writeFake(w, f.enrollStatus, f.enrollBody)
	case "/api/agent/v1/netmap":
		if f.netmapStatus != 0 {
			http.Error(w, "nope", f.netmapStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.netmapBody))
	case "/api/agent/v1/heartbeat":
		w.WriteHeader(f.heartbeatStatus)
	case "/api/agent/v1/services":
		if f.servicesStatus != 0 {
			http.Error(w, "conflict", f.servicesStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if f.servicesBody == "" {
			f.servicesBody = `{"services":[]}`
		}
		_, _ = w.Write([]byte(f.servicesBody))
	default:
		http.NotFound(w, req)
	}
}

func writeFake(w http.ResponseWriter, status int, body any) {
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TestEnrollRequestShape checks the enrollment request: version stamping, key
// encoding and no secrets in the URL.
func TestEnrollRequestShape(t *testing.T) {
	fake := &fakeControl{enrollBody: EnrollResponse{Status: "authorized", Token: "t", NodeID: 4, StableID: "n123"}}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	client := New(hs.URL + "/")
	machine, node := key.NewMachine(), key.NewNode()

	resp, err := client.Enroll(context.Background(), EnrollRequest{
		AuthKey:    "xunara_authkey_secret",
		MachineKey: machine.Public().String(),
		NodeKey:    node.Public().String(),
		Hostname:   "agent-host",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.Status != "authorized" || resp.Token != "t" || resp.NodeID != 4 {
		t.Fatalf("Enroll = %+v", resp)
	}

	got := fake.requests[0]
	if got.path != "/api/agent/v1/enroll" || got.contentType != "application/json" {
		t.Errorf("request = %+v", got)
	}
	if got.auth != "" {
		t.Errorf("enrollment sent an Authorization header: %q", got.auth)
	}
	if strings.Contains(string(got.raw), "xunara_authkey_secret") == false {
		t.Error("auth key missing from the request body")
	}

	var body EnrollRequest
	if err := json.Unmarshal(got.raw, &body); err != nil {
		t.Fatalf("decoding enroll body: %v", err)
	}
	if body.Version != Version {
		t.Errorf("version = %d, want %d", body.Version, Version)
	}
	if body.MachineKey != machine.Public().String() || body.NodeKey != node.Public().String() {
		t.Errorf("keys = %q / %q", body.MachineKey, body.NodeKey)
	}
}

// TestNetmapAndHeartbeatAuth checks the bearer credential and key binding on
// authenticated calls, and that the netmap decodes into tailcfg types.
func TestNetmapAndHeartbeatAuth(t *testing.T) {
	fake := &fakeControl{
		netmapBody:      `{"Node":{"Name":"agent.example.com.","ID":4},"Peers":[{"ID":5}]}`,
		heartbeatStatus: http.StatusNoContent,
	}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	client := New(hs.URL)
	machine, node := key.NewMachine(), key.NewNode()
	keys := Keys{Machine: machine, Node: node}

	netmap, err := client.Netmap(context.Background(), "secret-token", keys)
	if err != nil {
		t.Fatalf("Netmap: %v", err)
	}
	if netmap.Node == nil || netmap.Node.Name != "agent.example.com." || len(netmap.Peers) != 1 {
		t.Fatalf("netmap = %+v", netmap)
	}

	if err := client.Heartbeat(context.Background(), "secret-token", HeartbeatRequest{
		MachineKey: machine.Public().String(),
		NodeKey:    node.Public().String(),
		Hostname:   "agent-host",
	}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	for _, req := range fake.requests {
		if req.path == "/api/agent/v1/netmap" || req.path == "/api/agent/v1/heartbeat" {
			if req.auth != "Bearer secret-token" {
				t.Errorf("%s auth = %q, want the bearer token", req.path, req.auth)
			}
			if strings.Contains(req.raw2String(), "secret-token") {
				t.Errorf("%s put the token in the body", req.path)
			}
		}
		if strings.Contains(req.path, "secret-token") {
			t.Errorf("token leaked into the URL: %q", req.path)
		}
	}
}

// TestErrorMapping checks non-2xx handling, including the "re-enroll" signal.
func TestErrorMapping(t *testing.T) {
	fake := &fakeControl{netmapStatus: http.StatusUnauthorized}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	client := New(hs.URL)
	_, err := client.Netmap(context.Background(), "dead-token", Keys{Machine: key.NewMachine(), Node: key.NewNode()})
	if err == nil {
		t.Fatal("Netmap accepted a 401")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(%v) = false, want true", err)
	}

	fake2 := &fakeControl{enrollStatus: http.StatusForbidden, enrollBody: EnrollResponse{Status: "rejected", Error: "invalid pre-auth key"}}
	hs2 := httptest.NewServer(fake2)
	defer hs2.Close()

	_, err = New(hs2.URL).Enroll(context.Background(), EnrollRequest{
		AuthKey:    "bad",
		MachineKey: key.NewMachine().Public().String(),
		NodeKey:    key.NewNode().Public().String(),
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("enroll error = %v, want an HTTP 403 error", err)
	}
}

// TestServicesPublishShape checks the Atlas publish request: the bearer
// credential, the key binding and the declarative set, plus the response
// decode.
func TestServicesPublishShape(t *testing.T) {
	fake := &fakeControl{servicesBody: `{"services":[{
		"name":"api","protocol":"tcp","port":8080,
		"nodeId":7,"stableId":"n7","hostname":"agent","dnsName":"api.example.com",
		"created":"2026-10-01T00:00:00Z","updated":"2026-10-02T00:00:00Z"}]}`}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	client := New(hs.URL)
	machine, node := key.NewMachine(), key.NewNode()

	views, err := client.Services(context.Background(), "secret-token", Keys{Machine: machine, Node: node}, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	})
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %+v", views)
	}
	view := views[0]
	if view.Name != "api" || view.Protocol != "tcp" || view.Port != 8080 || view.DNSName != "api.example.com" {
		t.Errorf("view = %+v", view)
	}
	if view.NodeID != 7 || view.StableID != "n7" || view.Updated.IsZero() {
		t.Errorf("view bookkeeping = %+v", view)
	}

	got := fake.requests[0]
	if got.path != "/api/agent/v1/services" || got.contentType != "application/json" {
		t.Errorf("request = %+v", got)
	}
	if got.auth != "Bearer secret-token" {
		t.Errorf("auth = %q, want the bearer token", got.auth)
	}

	var body struct {
		MachineKey string    `json:"machine_key"`
		NodeKey    string    `json:"node_key"`
		Services   []Service `json:"services"`
	}
	if err := json.Unmarshal(got.raw, &body); err != nil {
		t.Fatalf("decoding services body: %v", err)
	}
	if body.MachineKey != machine.Public().String() || body.NodeKey != node.Public().String() {
		t.Errorf("keys = %q / %q", body.MachineKey, body.NodeKey)
	}
	if len(body.Services) != 1 || body.Services[0].Name != "api" || body.Services[0].Metadata["version"] != "1" {
		t.Errorf("services = %+v", body.Services)
	}
}

// TestServicesWithdrawAndError checks that a nil set withdraws everything on
// the wire and that a rejected publish surfaces the server's answer.
func TestServicesWithdrawAndError(t *testing.T) {
	fake := &fakeControl{}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	keys := Keys{Machine: key.NewMachine(), Node: key.NewNode()}
	if _, err := New(hs.URL).Services(context.Background(), "secret-token", keys, nil); err != nil {
		t.Fatalf("Services(nil): %v", err)
	}

	var body struct {
		Services []Service `json:"services"`
	}
	if err := json.Unmarshal(fake.requests[0].raw, &body); err != nil {
		t.Fatalf("decoding withdraw body: %v", err)
	}
	if body.Services == nil || len(body.Services) != 0 {
		t.Errorf("withdraw sent services = %#v, want an empty array", body.Services)
	}

	fake2 := &fakeControl{servicesStatus: http.StatusConflict}
	hs2 := httptest.NewServer(fake2)
	defer hs2.Close()

	_, err := New(hs2.URL).Services(context.Background(), "secret-token", keys, []Service{{Name: "api", Protocol: "tcp", Port: 80}})
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("Services conflict error = %v, want HTTP 409", err)
	}
	if IsUnauthorized(err) {
		t.Error("a 409 must not be read as a revoked credential")
	}
}

// raw2String renders a recorded body for leak assertions.
func (r recordedRequest) raw2String() string { return string(r.raw) }
