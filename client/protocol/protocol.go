// Package protocol is the Xunara Agent's client for /api/agent/v1, the native
// client protocol. It is separate from TS2021 on purpose: the native client
// speaks JSON over HTTPS, so nothing here can affect official-client
// compatibility (PROJECT_SPEC section 3).
package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Version is the wire version this client speaks.
const Version = 1

// defaultTimeout bounds one request. The agent retries on its own schedule, so
// a request must never hang forever.
const defaultTimeout = 30 * time.Second

// maxResponseBytes caps a response body; the netmap is the largest legitimate
// response and even a large tailnet fits comfortably.
const maxResponseBytes = 64 << 20

// maxErrorBytes caps the error text read from a failed response.
const maxErrorBytes = 4 << 10

// Client talks to one control server's agent API.
type Client struct {
	// BaseURL is the control server's base URL, e.g. "https://login.example.com".
	BaseURL string
	// HTTP is the client to use. Defaults to a client with a per-request
	// timeout.
	HTTP *http.Client
}

// New returns a client for baseURL.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: defaultTimeout},
	}
}

// EnrollRequest is the body of POST /api/agent/v1/enroll.
type EnrollRequest struct {
	Version int `json:"version"`
	// AuthKey is the pre-auth key that authorizes the machine. Empty starts
	// the interactive approval flow (Status becomes "pending").
	AuthKey    string `json:"auth_key,omitempty"`
	MachineKey string `json:"machine_key"`
	NodeKey    string `json:"node_key"`
	Hostname   string `json:"hostname,omitempty"`
	OS         string `json:"os,omitempty"`
	// AgentVersion is this binary's version.
	AgentVersion string `json:"agent_version,omitempty"`
	Ephemeral    bool   `json:"ephemeral,omitempty"`
}

// EnrollResponse is the answer to an enrollment attempt.
type EnrollResponse struct {
	Status   string `json:"status"`
	NodeID   int64  `json:"node_id,omitempty"`
	StableID string `json:"stable_id,omitempty"`
	AuthURL  string `json:"auth_url,omitempty"`
	Token    string `json:"token,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Enroll authorizes this agent. Pending means a human has to visit AuthURL;
// the caller retries Enroll until it returns "authorized".
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	req.Version = Version

	var resp EnrollResponse
	if err := c.postJSON(ctx, "/api/agent/v1/enroll", "", req, &resp); err != nil {
		return EnrollResponse{}, err
	}
	if resp.Status == "" {
		return EnrollResponse{}, errors.New("agent protocol: enrollment response has no status")
	}
	return resp, nil
}

// Keys is the machine identity an agent presents. Both keys are private
// material and must be persisted with restrictive permissions.
type Keys struct {
	Machine key.MachinePrivate
	Node    key.NodePrivate
}

// Netmap fetches the node's netmap as JSON.
func (c *Client) Netmap(ctx context.Context, token string, keys Keys) (*tailcfg.MapResponse, error) {
	body := keyBody{
		MachineKey: keys.Machine.Public().String(),
		NodeKey:    keys.Node.Public().String(),
	}

	var resp tailcfg.MapResponse
	if err := c.postJSON(ctx, "/api/agent/v1/netmap", token, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HeartbeatRequest reports liveness and host facts.
type HeartbeatRequest struct {
	MachineKey   string   `json:"machine_key"`
	NodeKey      string   `json:"node_key"`
	Hostname     string   `json:"hostname,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	AgentVersion string   `json:"agent_version,omitempty"`
}

// Heartbeat marks this agent online and reports host facts.
func (c *Client) Heartbeat(ctx context.Context, token string, req HeartbeatRequest) error {
	return c.postJSON(ctx, "/api/agent/v1/heartbeat", token, req, nil)
}

// keyBody is the common authenticated request body.
type keyBody struct {
	MachineKey string `json:"machine_key"`
	NodeKey    string `json:"node_key"`
}

// postJSON sends req and decodes the response into out (when non-nil). The
// token goes in the Authorization header, never a URL (AGENTS.md section 8).
func (c *Client) postJSON(ctx context.Context, path, token string, req, out any) error {
	if c.BaseURL == "" {
		return errors.New("agent protocol: no server URL")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	raw, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("agent protocol: encoding request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("agent protocol: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "xunara-agent")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("agent protocol: %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(msg)),
		}
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("agent protocol: decoding %s response: %w", path, err)
	}
	return nil
}

// HTTPError is a non-2xx response from the control server.
type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("agent protocol: server returned %s", e.Status)
	}
	return fmt.Sprintf("agent protocol: server returned %s: %s", e.Status, e.Body)
}

// IsUnauthorized reports whether err is a 401 or 403: the credential is gone
// or no longer valid, so the agent must enroll again.
func IsUnauthorized(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	return he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusForbidden
}
