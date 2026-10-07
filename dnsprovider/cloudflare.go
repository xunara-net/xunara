package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultCloudflareAPI is the public Cloudflare API endpoint. Tests override
// it with a local server.
const defaultCloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare updates a zone through the Cloudflare API v4 using a scoped API
// token. The token should carry only Zone:DNS:Edit for the one zone.
type Cloudflare struct {
	// APIToken is the scoped API token. It is never logged.
	APIToken string
	// Zone is the zone name, e.g. "example.com".
	Zone string
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
	// Client optionally overrides the HTTP client.
	Client *http.Client

	mu     sync.Mutex
	zoneID string
}

// NewCloudflare builds a Cloudflare provider. The token comes from the
// environment in production code.
func NewCloudflare(zone, apiToken string) (*Cloudflare, error) {
	zone = strings.Trim(strings.TrimSpace(zone), ".")
	if zone == "" || !strings.Contains(zone, ".") {
		return nil, fmt.Errorf("dnsprovider: invalid Cloudflare zone %q", zone)
	}
	if strings.TrimSpace(apiToken) == "" {
		return nil, ErrMissingToken
	}
	return &Cloudflare{APIToken: apiToken, Zone: zone}, nil
}

func (c *Cloudflare) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultCloudflareAPI
}

func (c *Cloudflare) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

// cfEnvelope is the Cloudflare API response wrapper.
type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e cfEnvelope) err(op string) error {
	if e.Success {
		return nil
	}
	msgs := make([]string, 0, len(e.Errors))
	for _, item := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d %s", item.Code, item.Message))
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "unknown error")
	}
	return fmt.Errorf("dnsprovider: cloudflare %s: %s", op, strings.Join(msgs, "; "))
}

// do performs an API request and decodes the envelope. body may be nil.
func (c *Cloudflare) do(ctx context.Context, method, path string, body any, op string) (*cfEnvelope, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnsprovider: cloudflare %s: %w", op, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("dnsprovider: cloudflare %s: %w", op, err)
	}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("dnsprovider: cloudflare %s: unexpected response: %w", op, err)
	}
	if err := env.err(op); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("dnsprovider: cloudflare %s: unexpected status %s", op, resp.Status)
	}
	return &env, nil
}

// zoneID resolves (and caches) the zone's identifier.
func (c *Cloudflare) zoneIDFor(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.zoneID != "" {
		id := c.zoneID
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	env, err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(c.Zone), nil, "lookup zone")
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("dnsprovider: cloudflare lookup zone: %w", err)
	}
	if len(zones) == 0 || zones[0].ID == "" {
		return "", fmt.Errorf("dnsprovider: cloudflare zone %q not found", c.Zone)
	}

	c.mu.Lock()
	c.zoneID = zones[0].ID
	c.mu.Unlock()
	return zones[0].ID, nil
}

// listTXT returns the record IDs of TXT records at name.
func (c *Cloudflare) listTXT(ctx context.Context, name string) ([]string, error) {
	zoneID, err := c.zoneIDFor(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", url.PathEscape(zoneID), url.QueryEscape(name))
	env, err := c.do(ctx, http.MethodGet, path, nil, "list records")
	if err != nil {
		return nil, err
	}
	var records []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Result, &records); err != nil {
		return nil, fmt.Errorf("dnsprovider: cloudflare list records: %w", err)
	}
	ids := make([]string, 0, len(records))
	for _, r := range records {
		if r.ID != "" {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// PutTXT replaces every TXT record at name with a single record carrying
// value. ACME requires the challenge value to be visible immediately, so the
// update is not cached.
func (c *Cloudflare) PutTXT(ctx context.Context, name, value string) error {
	if err := validateRecordName(name); err != nil {
		return err
	}

	// Clear any stale challenge values first: a second DNS-01 attempt must
	// not leave the old value behind for the CA to read.
	if err := c.DeleteTXT(ctx, name); err != nil {
		return err
	}

	zoneID, err := c.zoneIDFor(ctx)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID)), map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     60,
	}, "create record")
	return err
}

// DeleteTXT removes the TXT records at name. Deleting nothing is not an error.
func (c *Cloudflare) DeleteTXT(ctx context.Context, name string) error {
	if err := validateRecordName(name); err != nil {
		return err
	}
	zoneID, err := c.zoneIDFor(ctx)
	if err != nil {
		return err
	}
	ids, err := c.listTXT(ctx, name)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := c.do(ctx, http.MethodDelete,
			fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(id)), nil, "delete record"); err != nil {
			return err
		}
	}
	return nil
}
