package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// admit asks a test server's /derp/admit endpoint and decodes the response.
func admit(t *testing.T, url string, req tailcfg.DERPAdmitClientRequest) (tailcfg.DERPAdmitClientResponse, int) {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshalling admission request: %v", err)
	}
	resp, err := http.Post(url+"/derp/admit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /derp/admit: %v", err)
	}
	defer resp.Body.Close()

	var res tailcfg.DERPAdmitClientResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("decoding admission response: %v", err)
		}
	}
	return res, resp.StatusCode
}

func TestDERPAdmitRegisteredNode(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	node := seedTestNode(t, s)

	res, status := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{
		NodePublic: node.NodeKey,
		Source:     netip.MustParseAddr("100.64.0.1"),
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !res.Allow {
		t.Fatal("registered node key was not admitted")
	}
}

func TestDERPAdmitUnknownNode(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	res, status := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{
		NodePublic: key.NewNode().Public(),
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if res.Allow {
		t.Fatal("unknown node key was admitted")
	}
}

func TestDERPAdmitExpiredNode(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	node := seedTestNode(t, s)
	node.Expiry = time.Now().Add(-time.Hour)
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("expiring node: %v", err)
	}

	res, status := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{NodePublic: node.NodeKey})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if res.Allow {
		t.Fatal("expired node key was admitted")
	}
}

func TestDERPAdmitZeroKeyIsDenied(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	res, status := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if res.Allow {
		t.Fatal("zero node key was admitted")
	}
}

func TestDERPAdmitMalformedRequest(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	resp, err := http.Post(hs.URL+"/derp/admit", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST /derp/admit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	resp, err = http.Post(hs.URL+"/derp/admit", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /derp/admit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body status = %d, want 400", resp.StatusCode)
	}
}
