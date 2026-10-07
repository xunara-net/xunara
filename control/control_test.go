package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

// newTestServer builds a Server backed by a temporary state directory.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newServerAt(t, t.TempDir())
}

// newServerAt builds a Server rooted at a specific state directory, so tests
// can restart it against the same durable state.
func newServerAt(t *testing.T, stateDir string) *Server {
	t.Helper()

	return newServerWithConfig(t, Config{StateDir: stateDir})
}

// newServerWithConfig builds a Server with an explicit config, filling in test
// defaults for anything the caller left blank.
func newServerWithConfig(t *testing.T, cfg Config) *Server {
	t.Helper()

	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://login.test"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// fetchControlKey retrieves the server's Noise public key via GET /key.
func fetchControlKey(t *testing.T, baseURL string) key.MachinePublic {
	t.Helper()

	resp, err := http.Get(baseURL + "/key?v=" + strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	if err != nil {
		t.Fatalf("GET /key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /key status = %d (%s)", resp.StatusCode, body)
	}

	var pk tailcfg.OverTLSPublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		t.Fatalf("decoding /key response: %v", err)
	}
	return pk.PublicKey
}

// dialNoise performs a real TS2021 Noise handshake against hs, exactly as an
// official Tailscale client would, and returns the established connection with
// the early-noise payload already consumed.
func dialNoise(t *testing.T, hs *httptest.Server, machineKey key.MachinePrivate) net.Conn {
	t.Helper()

	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	controlKey := fetchControlKey(t, hs.URL)

	d := &controlhttp.Dialer{
		Hostname:        u.Hostname(),
		MachineKey:      machineKey,
		ControlKey:      controlKey,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		HTTPPort:        u.Port(),
		HTTPSPort:       controlhttp.NoPort,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("tcp", hs.Listener.Addr().String())
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("noise dial: %v", err)
	}

	// The server writes a version-gated early-noise payload between the
	// handshake and the HTTP/2 session; upstream clients consume it with the
	// ts2021.Conn wrapper. Doing the same here keeps the test honest.
	nc := ts2021.NewConn(conn.Conn, func() {})
	early, err := nc.GetEarlyPayload(ctx)
	if err != nil {
		t.Fatalf("reading early noise payload: %v", err)
	}
	if early == nil {
		t.Fatal("server did not send an early noise payload")
	}
	if early.NodeKeyChallenge.IsZero() {
		t.Error("early noise payload carries a zero node key challenge")
	}
	return nc
}

// h2Client returns an HTTP/2 client that tunnels requests over conn.
//
// A connection must have exactly one such client: a second transport over the
// same net.Conn would re-send the HTTP/2 connection preface. Request deadlines
// therefore come from the request context, not http.Client.Timeout.
func h2Client(conn net.Conn) *http.Client {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return conn, nil
		},
	}
	return &http.Client{Transport: tr}
}

// postRaw POSTs req as JSON to path over client and returns the response body.
func postRaw(t *testing.T, client *http.Client, path string, req any) []byte {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshalling %s request: %v", path, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://xunara.test"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building %s request: %v", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s response: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, body = %s", path, resp.StatusCode, out)
	}
	return out
}

// postRawStatus is postRaw but returns the status code instead of failing on
// non-200 responses.
func postRawStatus(t *testing.T, client *http.Client, path string, req any) ([]byte, int) {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshalling %s request: %v", path, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://xunara.test"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building %s request: %v", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s response: %v", path, err)
	}
	return out, resp.StatusCode
}

// decodeJSON decodes a JSON response body into T.
func decodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding JSON: %v (body=%s)", err, body)
	}
	return out
}

// decodeMapResponse validates the length prefix and (optional) zstd framing of
// a MapResponse body and decodes it.
func decodeMapResponse(t *testing.T, body []byte, compress string) *tailcfg.MapResponse {
	t.Helper()

	if len(body) < reservedResponseHeaderSize {
		t.Fatalf("map response too short: %d bytes", len(body))
	}
	n := binary.LittleEndian.Uint32(body[:reservedResponseHeaderSize])
	payload := body[reservedResponseHeaderSize:]
	if int(n) != len(payload) {
		t.Fatalf("length prefix = %d, payload = %d", n, len(payload))
	}

	if compress == "zstd" {
		decoded, err := zstdframe.AppendDecode(nil, payload)
		if err != nil {
			t.Fatalf("zstd decode: %v", err)
		}
		payload = decoded
	}

	var msg tailcfg.MapResponse
	if err := json.Unmarshal(payload, &msg); err != nil {
		t.Fatalf("decoding map response: %v", err)
	}
	return &msg
}
