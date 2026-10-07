package identity

import (
	"errors"
	"time"
)

// WebhookEndpoint is an operator-managed webhook receiver.
//
// The signing secret is opaque to the trust plane: the control plane seals it
// before storing it, so a database dump never contains a usable secret
// (AGENTS.md section 8). Only the control plane, which owns the sealing key,
// can turn Secret back into the value used to sign deliveries.
type WebhookEndpoint struct {
	// ID is the stable identifier and the delivery-cursor key. Renaming is
	// not supported: it would replay the whole audit log.
	ID string
	// URL is the receiver. HTTPS, or loopback HTTP for tests.
	URL string
	// Secret is the sealed signing secret.
	Secret string
	// Events filters on the audit action (globs, "*" only). Empty means all.
	Events []string
	// Enabled keeps a receiver configured but paused; a paused endpoint does
	// not deliver.
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrWebhookEndpointExists is returned when an endpoint ID is already in use.
var ErrWebhookEndpointExists = errors.New("identity: webhook endpoint already exists")

// WebhookEndpointStore is the durable table of operator-managed webhook
// receivers, separate from the deployment-configured ones.
type WebhookEndpointStore interface {
	// CreateWebhookEndpoint stores a new endpoint, assigning timestamps.
	CreateWebhookEndpoint(e *WebhookEndpoint) error
	// GetWebhookEndpoint returns an endpoint by ID.
	GetWebhookEndpoint(id string) (WebhookEndpoint, bool)
	// ListWebhookEndpoints returns every endpoint, oldest first.
	ListWebhookEndpoints() []WebhookEndpoint
	// UpdateWebhookEndpoint replaces an endpoint. It fails when the endpoint
	// is unknown.
	UpdateWebhookEndpoint(e WebhookEndpoint) error
	// DeleteWebhookEndpoint removes an endpoint and its delivery cursor.
	DeleteWebhookEndpoint(id string) error
}
