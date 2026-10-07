package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Webhook is a Provider that asks an operator-run HTTP endpoint to update the
// zone. It is the generic integration point for DNS servers Xunara has no
// first-class adapter for.
//
// The endpoint receives JSON POSTs:
//
//	{"action":"put","name":"_acme-challenge.example.com","type":"TXT","value":"..."}
//	{"action":"delete","name":"_acme-challenge.example.com","type":"TXT"}
//
// and must answer 2xx when the record was applied. Any other status is an
// error and the ACME challenge fails closed.
type Webhook struct {
	// URL of the update endpoint. Must be https (or loopback http).
	URL string
	// Token, when non-empty, is sent as "Authorization: Bearer <token>".
	Token string
	// Client optionally overrides the HTTP client.
	Client *http.Client
}

// NewWebhook validates rawURL and builds a Webhook provider.
func NewWebhook(rawURL, token string) (*Webhook, error) {
	u, err := ValidateHTTPURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &Webhook{URL: u.String(), Token: token}, nil
}

type webhookRequest struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
}

// PutTXT creates or replaces the TXT record.
func (w *Webhook) PutTXT(ctx context.Context, name, value string) error {
	if err := validateRecordName(name); err != nil {
		return err
	}
	return w.send(ctx, webhookRequest{Action: "put", Name: name, Type: "TXT", Value: value})
}

// DeleteTXT removes the TXT record.
func (w *Webhook) DeleteTXT(ctx context.Context, name string) error {
	if err := validateRecordName(name); err != nil {
		return err
	}
	return w.send(ctx, webhookRequest{Action: "delete", Name: name, Type: "TXT"})
}

func (w *Webhook) send(ctx context.Context, body webhookRequest) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dnsprovider: webhook %s: %w", body.Action, err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused without letting
	// the endpoint stream unbounded data at us.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("dnsprovider: webhook %s: unexpected status %s", body.Action, resp.Status)
	}
	return nil
}
