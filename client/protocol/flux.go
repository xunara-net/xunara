package protocol

// This file is the native client's half of Xunara Flux (PROJECT_SPEC section
// 25): offering, accepting and moving files between agents through the
// control plane, which relays ciphertext it cannot read. Sealing and opening
// content lives in client/flux; this layer only speaks HTTP.
//
// Flux requests carry the credential in the Authorization header and the
// machine/node public keys in X-Xunara-* headers, exactly like the event
// stream: GET, PUT and opaque binary bodies have no JSON place for them. The
// keys are public material, never secrets.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fluxContentTimeout bounds one content upload or download; the body may be
// up to the server's file size ceiling, so the ordinary request timeout is
// too tight for slow links.
const fluxContentTimeout = 5 * time.Minute

// maxFluxContentBytes caps a downloaded body. It is the control plane's hard
// file size ceiling plus the format overhead and slack: a server that sends
// more than this is broken or hostile, and the recipient refuses oversized
// content before decrypting it anyway.
const maxFluxContentBytes = (64 << 20) + (1 << 20)

// Flux transfer states as the agent API reports them. They mirror
// state.FluxTransferState; the client keeps its own copies so the two halves
// can move independently.
const (
	FluxPending   = "pending"
	FluxAccepted  = "accepted"
	FluxUploaded  = "uploaded"
	FluxCompleted = "completed"
	FluxDenied    = "denied"
	FluxFailed    = "failed"
	FluxCancelled = "cancelled"
	FluxExpired   = "expired"
)

// FluxActive reports whether a transfer still holds resources or waits for an
// action (the counterpart of state.FluxTransferState.Active).
func FluxActive(state string) bool {
	switch state {
	case FluxPending, FluxAccepted, FluxUploaded:
		return true
	default:
		return false
	}
}

// FluxTransfer is one transfer as the control plane reports it. Content and
// private key material never appear here; RecipientKey is the recipient's
// per-transfer public key and is only present after it accepted.
type FluxTransfer struct {
	ID        string `json:"id"`
	Direction string `json:"direction"`
	State     string `json:"state"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	// SenderNodeID and SenderHostname describe the sending node.
	SenderNodeID   string `json:"senderNodeId"`
	SenderHostname string `json:"senderHostname"`
	// RecipientNodeID and RecipientHostname describe the receiving node.
	RecipientNodeID   string `json:"recipientNodeId"`
	RecipientHostname string `json:"recipientHostname"`
	// RecipientKey is the recipient's per-transfer X25519 public key,
	// base64-encoded; empty until the recipient accepts.
	RecipientKey string    `json:"recipientKey,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Peer is the other end of the transfer, which depends on the direction.
func (t FluxTransfer) Peer() string {
	if t.Direction == "sent" {
		return t.RecipientHostname
	}
	return t.SenderHostname
}

// FluxOffer is the metadata a sender proposes before any content moves.
type FluxOffer struct {
	// Recipient is the receiving node's stable ID.
	Recipient string `json:"recipient"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

// CreateFluxTransfer offers a file to another node (POST /flux/transfers).
func (c *Client) CreateFluxTransfer(ctx context.Context, token string, keys Keys, offer FluxOffer) (FluxTransfer, error) {
	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, "/api/agent/v1/flux/transfers", token, keys, offer, &transfer)
	return transfer, err
}

// ListFluxTransfers fetches every transfer this node takes part in, newest
// first (GET /flux/transfers).
func (c *Client) ListFluxTransfers(ctx context.Context, token string, keys Keys) ([]FluxTransfer, error) {
	var resp struct {
		Transfers []FluxTransfer `json:"transfers"`
	}
	if err := c.doFluxJSON(ctx, http.MethodGet, "/api/agent/v1/flux/transfers", token, keys, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Transfers, nil
}

// AcceptFluxTransfer accepts an inbound offer and publishes the public half
// of this transfer's recipient key (POST /flux/transfers/{id}/accept). Only
// the recipient can accept.
func (c *Client) AcceptFluxTransfer(ctx context.Context, token string, keys Keys, id string, publicKey []byte) (FluxTransfer, error) {
	body := struct {
		PublicKey string `json:"publicKey"`
	}{PublicKey: base64.StdEncoding.EncodeToString(publicKey)}

	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, fluxPath(id, "accept"), token, keys, body, &transfer)
	return transfer, err
}

// DenyFluxTransfer refuses an inbound offer (POST /flux/transfers/{id}/deny).
// The optional reason is a static, printable explanation for the sender.
func (c *Client) DenyFluxTransfer(ctx context.Context, token string, keys Keys, id, reason string) (FluxTransfer, error) {
	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, fluxPath(id, "deny"), token, keys, reasonBody(reason), &transfer)
	return transfer, err
}

// CancelFluxTransfer withdraws an offer the sender made (POST
// /flux/transfers/{id}/cancel). Only the sender can cancel.
func (c *Client) CancelFluxTransfer(ctx context.Context, token string, keys Keys, id string) (FluxTransfer, error) {
	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, fluxPath(id, "cancel"), token, keys, nil, &transfer)
	return transfer, err
}

// CompleteFluxTransfer confirms to the control plane that the recipient
// decrypted and verified the content (POST /flux/transfers/{id}/complete).
// The control plane deletes the ciphertext in response.
func (c *Client) CompleteFluxTransfer(ctx context.Context, token string, keys Keys, id string) (FluxTransfer, error) {
	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, fluxPath(id, "complete"), token, keys, nil, &transfer)
	return transfer, err
}

// FailFluxTransfer reports that the recipient could not decrypt or verify the
// content (POST /flux/transfers/{id}/fail). The reason is shown to the sender.
func (c *Client) FailFluxTransfer(ctx context.Context, token string, keys Keys, id, reason string) (FluxTransfer, error) {
	var transfer FluxTransfer
	err := c.doFluxJSON(ctx, http.MethodPost, fluxPath(id, "fail"), token, keys, reasonBody(reason), &transfer)
	return transfer, err
}

// UploadFluxContent sends the sealed content (PUT /flux/transfers/{id}/content).
// The server bounds the body by the declared size and stores it verbatim.
func (c *Client) UploadFluxContent(ctx context.Context, token string, keys Keys, id string, content io.Reader) (FluxTransfer, error) {
	ctx, cancel := context.WithTimeout(ctx, fluxContentTimeout)
	defer cancel()

	req, err := c.fluxRequest(ctx, http.MethodPut, fluxPath(id, "content"), token, keys, content)
	if err != nil {
		return FluxTransfer{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	var transfer FluxTransfer
	if _, err := c.doFluxRequest(c.contentHTTPClient(), req, &transfer); err != nil {
		return FluxTransfer{}, err
	}
	return transfer, nil
}

// DownloadFluxContent fetches the sealed content (GET
// /flux/transfers/{id}/content). The download may be retried until the
// transfer completes; the body is bounded by the transfer's declared size
// plus the format overhead.
func (c *Client) DownloadFluxContent(ctx context.Context, token string, keys Keys, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fluxContentTimeout)
	defer cancel()

	req, err := c.fluxRequest(ctx, http.MethodGet, fluxPath(id, "content"), token, keys, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doFluxRequest(c.contentHTTPClient(), req, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFluxContentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("agent protocol: reading flux content: %w", err)
	}
	if len(raw) > maxFluxContentBytes {
		return nil, fmt.Errorf("agent protocol: flux content exceeds %d bytes", maxFluxContentBytes)
	}
	return raw, nil
}

// reasonBody is the JSON payload of denials and failures; an empty reason is
// fine for both endpoints.
func reasonBody(reason string) any {
	return struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: reason}
}

// fluxPath builds a transfer sub-resource path. The ID is server-generated;
// it is escaped so a malformed one cannot alter the path.
func fluxPath(id, action string) string {
	return "/api/agent/v1/flux/transfers/" + url.PathEscape(id) + "/" + action
}

// doFluxJSON performs a Flux call with a JSON body (or none) and decodes the
// JSON response into out.
func (c *Client) doFluxJSON(ctx context.Context, method, path, token string, keys Keys, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agent protocol: encoding request: %w", err)
		}
	}
	req, err := c.fluxRequest(ctx, method, path, token, keys, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	_, err = c.doFluxRequest(c.defaultHTTPClient(), req, out)
	return err
}

// defaultHTTPClient is the client for ordinary Flux calls.
func (c *Client) defaultHTTPClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultTimeout}
}

// contentHTTPClient is the client for a content move: its timeout must fit
// the body, and it must not be tighter than the request context's own budget.
// A copy is used, so the caller's client keeps its settings.
func (c *Client) contentHTTPClient() *http.Client {
	client := c.defaultHTTPClient()
	if client.Timeout >= fluxContentTimeout {
		return client
	}
	clone := *client
	clone.Timeout = fluxContentTimeout
	return &clone
}

// fluxRequest builds one Flux request with the credential in headers.
func (c *Client) fluxRequest(ctx context.Context, method, path, token string, keys Keys, body io.Reader) (*http.Request, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("agent protocol: no server URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("agent protocol: building request: %w", err)
	}
	req.Header.Set("User-Agent", "xunara-agent")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// A Flux call carries no keys in its body (it may be binary), so the
	// credential is bound to the key pair through headers.
	req.Header.Set("X-Xunara-Machine-Key", keys.Machine.Public().String())
	req.Header.Set("X-Xunara-Node-Key", keys.Node.Public().String())
	return req, nil
}

// doFluxRequest runs a request built by [Client.fluxRequest] with the given
// client. When out is non-nil the response is JSON and is decoded into it;
// otherwise the caller owns the body.
func (c *Client) doFluxRequest(client *http.Client, req *http.Request, out any) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent protocol: %s %s: %w", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(msg)),
		}
	}
	if out == nil {
		return resp, nil
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return nil, fmt.Errorf("agent protocol: decoding %s response: %w", req.URL.Path, err)
	}
	return resp, nil
}
