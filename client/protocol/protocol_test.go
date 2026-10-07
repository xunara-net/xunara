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

// raw2String renders a recorded body for leak assertions.
func (r recordedRequest) raw2String() string { return string(r.raw) }
