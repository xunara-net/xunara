package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

// fluxRecorder answers Flux endpoints and records what it saw.
type fluxRecorder struct {
	requests []fluxRequestRecord

	status int
	body   string
}

type fluxRequestRecord struct {
	method      string
	path        string
	auth        string
	machineKey  string
	nodeKey     string
	contentType string
	raw         []byte
}

func (f *fluxRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, fluxRequestRecord{
		method:      req.Method,
		path:        req.URL.Path,
		auth:        req.Header.Get("Authorization"),
		machineKey:  req.Header.Get("X-Xunara-Machine-Key"),
		nodeKey:     req.Header.Get("X-Xunara-Node-Key"),
		contentType: req.Header.Get("Content-Type"),
		raw:         raw,
	})

	if f.status >= 400 {
		http.Error(w, "flux error", f.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.body != "" {
		_, _ = w.Write([]byte(f.body))
		return
	}
	_, _ = w.Write([]byte(`{"id":"fx_0123456789abcdef0123456789abcdef","direction":"sent","state":"pending","name":"report.txt","size":3,"sha256":"` + strings.Repeat("ab", 32) + `"}`))
}

func fluxTestClient(t *testing.T, rec *fluxRecorder) (*Client, Keys, string) {
	t.Helper()
	hs := httptest.NewServer(rec)
	t.Cleanup(hs.Close)
	return New(hs.URL), Keys{Machine: key.NewMachine(), Node: key.NewNode()}, "tok"
}

func TestCreateFluxTransferRequestShape(t *testing.T) {
	rec := &fluxRecorder{}
	client, keys, token := fluxTestClient(t, rec)

	got, err := client.CreateFluxTransfer(context.Background(), token, keys, FluxOffer{
		Recipient: "n0123456789abcdef",
		Name:      "report.txt",
		Size:      3,
		SHA256:    strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("CreateFluxTransfer: %v", err)
	}
	if got.ID != "fx_0123456789abcdef0123456789abcdef" || got.State != FluxPending {
		t.Fatalf("CreateFluxTransfer = %+v", got)
	}

	req := rec.requests[0]
	if req.method != http.MethodPost || req.path != "/api/agent/v1/flux/transfers" {
		t.Errorf("request = %s %s", req.method, req.path)
	}
	if req.contentType != "application/json" {
		t.Errorf("content type = %q", req.contentType)
	}
	if req.auth != "Bearer "+token {
		t.Errorf("authorization = %q", req.auth)
	}
	if req.machineKey != keys.Machine.Public().String() || req.nodeKey != keys.Node.Public().String() {
		t.Errorf("key headers = %q / %q", req.machineKey, req.nodeKey)
	}
	if strings.Contains(string(req.raw), "tok") || strings.Contains(req.path, "tok") {
		t.Error("the agent credential leaked into the body or URL")
	}

	var body FluxOffer
	if err := json.Unmarshal(req.raw, &body); err != nil {
		t.Fatalf("decoding offer: %v", err)
	}
	if body.Recipient != "n0123456789abcdef" || body.Name != "report.txt" || body.Size != 3 {
		t.Errorf("offer = %+v", body)
	}
}

func TestListFluxTransfers(t *testing.T) {
	rec := &fluxRecorder{body: `{"transfers":[{"id":"fx_1","state":"accepted","direction":"received","recipientKey":"AAAA"}]}`}
	client, keys, token := fluxTestClient(t, rec)

	transfers, err := client.ListFluxTransfers(context.Background(), token, keys)
	if err != nil {
		t.Fatalf("ListFluxTransfers: %v", err)
	}
	if len(transfers) != 1 || transfers[0].ID != "fx_1" || transfers[0].RecipientKey != "AAAA" {
		t.Fatalf("ListFluxTransfers = %+v", transfers)
	}
	req := rec.requests[0]
	if req.method != http.MethodGet || req.path != "/api/agent/v1/flux/transfers" {
		t.Errorf("request = %s %s", req.method, req.path)
	}
	if len(req.raw) != 0 {
		t.Errorf("GET sent a body: %q", req.raw)
	}
	if transfers[0].Peer() != "" {
		t.Errorf("Peer() = %q for a transfer without hostnames", transfers[0].Peer())
	}
}

func TestFluxTransitionBodies(t *testing.T) {
	publicKey := bytes.Repeat([]byte{7}, 32)

	cases := []struct {
		name  string
		path  string
		call  func(*Client, Keys, string) (FluxTransfer, error)
		check func(*testing.T, fluxRequestRecord)
	}{
		{
			name: "accept",
			path: "/api/agent/v1/flux/transfers/fx_1/accept",
			call: func(c *Client, keys Keys, token string) (FluxTransfer, error) {
				return c.AcceptFluxTransfer(context.Background(), token, keys, "fx_1", publicKey)
			},
			check: func(t *testing.T, req fluxRequestRecord) {
				var body struct {
					PublicKey string `json:"publicKey"`
				}
				if err := json.Unmarshal(req.raw, &body); err != nil {
					t.Fatalf("decoding accept body: %v", err)
				}
				raw, err := base64.StdEncoding.DecodeString(body.PublicKey)
				if err != nil || !bytes.Equal(raw, publicKey) {
					t.Fatalf("publicKey = %q (%v)", body.PublicKey, err)
				}
			},
		},
		{
			name: "deny",
			path: "/api/agent/v1/flux/transfers/fx_1/deny",
			call: func(c *Client, keys Keys, token string) (FluxTransfer, error) {
				return c.DenyFluxTransfer(context.Background(), token, keys, "fx_1", "not now")
			},
			check: func(t *testing.T, req fluxRequestRecord) {
				if !strings.Contains(string(req.raw), `"reason":"not now"`) {
					t.Fatalf("deny body = %s", req.raw)
				}
			},
		},
		{
			name: "cancel",
			path: "/api/agent/v1/flux/transfers/fx_1/cancel",
			call: func(c *Client, keys Keys, token string) (FluxTransfer, error) {
				return c.CancelFluxTransfer(context.Background(), token, keys, "fx_1")
			},
			check: func(t *testing.T, req fluxRequestRecord) {
				if len(req.raw) != 0 {
					t.Fatalf("cancel sent a body: %q", req.raw)
				}
			},
		},
		{
			name: "complete",
			path: "/api/agent/v1/flux/transfers/fx_1/complete",
			call: func(c *Client, keys Keys, token string) (FluxTransfer, error) {
				return c.CompleteFluxTransfer(context.Background(), token, keys, "fx_1")
			},
			check: func(t *testing.T, req fluxRequestRecord) {
				if len(req.raw) != 0 {
					t.Fatalf("complete sent a body: %q", req.raw)
				}
			},
		},
		{
			name: "fail",
			path: "/api/agent/v1/flux/transfers/fx_1/fail",
			call: func(c *Client, keys Keys, token string) (FluxTransfer, error) {
				return c.FailFluxTransfer(context.Background(), token, keys, "fx_1", "sha256 mismatch")
			},
			check: func(t *testing.T, req fluxRequestRecord) {
				if !strings.Contains(string(req.raw), `"reason":"sha256 mismatch"`) {
					t.Fatalf("fail body = %s", req.raw)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fluxRecorder{}
			client, keys, token := fluxTestClient(t, rec)

			if _, err := tc.call(client, keys, token); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			req := rec.requests[0]
			if req.method != http.MethodPost || req.path != tc.path {
				t.Errorf("request = %s %s, want POST %s", req.method, req.path, tc.path)
			}
			if req.auth != "Bearer "+token {
				t.Errorf("authorization = %q", req.auth)
			}
			tc.check(t, req)
		})
	}
}

func TestUploadFluxContent(t *testing.T) {
	rec := &fluxRecorder{}
	client, keys, token := fluxTestClient(t, rec)

	content := []byte("sealed bytes")
	got, err := client.UploadFluxContent(context.Background(), token, keys, "fx_1", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("UploadFluxContent: %v", err)
	}
	if got.ID != "fx_0123456789abcdef0123456789abcdef" {
		t.Fatalf("UploadFluxContent = %+v", got)
	}

	req := rec.requests[0]
	if req.method != http.MethodPut || req.path != "/api/agent/v1/flux/transfers/fx_1/content" {
		t.Errorf("request = %s %s", req.method, req.path)
	}
	if req.contentType != "application/octet-stream" {
		t.Errorf("content type = %q", req.contentType)
	}
	if !bytes.Equal(req.raw, content) {
		t.Errorf("body = %q, want %q", req.raw, content)
	}
}

func TestDownloadFluxContent(t *testing.T) {
	content := []byte("sealed bytes")
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/agent/v1/flux/transfers/fx_1/content" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(content)
	}))
	defer hs.Close()

	client := New(hs.URL)
	keys := Keys{Machine: key.NewMachine(), Node: key.NewNode()}
	got, err := client.DownloadFluxContent(context.Background(), "tok", keys, "fx_1")
	if err != nil {
		t.Fatalf("DownloadFluxContent: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("DownloadFluxContent = %q", got)
	}
}

func TestFluxErrorMapping(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests} {
		rec := &fluxRecorder{status: status}
		client, keys, token := fluxTestClient(t, rec)

		_, err := client.ListFluxTransfers(context.Background(), token, keys)
		var he *HTTPError
		if !errors.As(err, &he) || he.StatusCode != status {
			t.Fatalf("status %d: error = %v", status, err)
		}
	}
}

func TestFluxUnauthorized(t *testing.T) {
	rec := &fluxRecorder{status: http.StatusUnauthorized}
	client, keys, token := fluxTestClient(t, rec)

	_, err := client.ListFluxTransfers(context.Background(), token, keys)
	if !IsUnauthorized(err) {
		t.Fatalf("ListFluxTransfers = %v, want unauthorized", err)
	}
}

func TestFluxActiveStates(t *testing.T) {
	for _, state := range []string{FluxPending, FluxAccepted, FluxUploaded} {
		if !FluxActive(state) {
			t.Errorf("FluxActive(%q) = false", state)
		}
	}
	for _, state := range []string{FluxCompleted, FluxDenied, FluxFailed, FluxCancelled, FluxExpired, "bogus"} {
		if FluxActive(state) {
			t.Errorf("FluxActive(%q) = true", state)
		}
	}
}
