package identity

import (
	"errors"

	"tailscale.com/tailcfg"
)

// ErrUserNotFound is returned when a user ID or login name does not resolve.
var ErrUserNotFound = errors.New("identity: user not found")

// ErrExternalIdentityExists is returned when (provider, subject) is already
// linked to a different user.
var ErrExternalIdentityExists = errors.New("identity: external identity already linked")

// ErrLoginNameTaken is returned when a login name is already in use.
var ErrLoginNameTaken = errors.New("identity: login name already taken")

// UserStore is the human-identity half of the trust plane.
type UserStore interface {
	// CreateUser stores a user, assigning its ID and timestamps.
	CreateUser(u *User) error
	// GetUser returns a user by ID.
	GetUser(id tailcfg.UserID) (User, bool)
	// GetUserByLoginName returns a user by login name, case-insensitively.
	GetUserByLoginName(login string) (User, bool)
	// ListUsers returns every user, oldest first.
	ListUsers() []User
	// UpdateUser replaces a stored user. It fails if the user is unknown.
	UpdateUser(u User) error
	// DeleteUser removes a user and its external identity links. It fails
	// with ErrUserNotFound if the user is unknown.
	DeleteUser(id tailcfg.UserID) error
}

// ExternalIdentityStore is the link between external accounts and users.
//
// The lookup key is (provider, subject) and nothing else: see AGENTS.md
// section 6.
type ExternalIdentityStore interface {
	// LinkExternalIdentity attaches an external account to a user. It fails
	// with ErrExternalIdentityExists when the account is already linked to a
	// different user.
	LinkExternalIdentity(ei *ExternalIdentity) error
	// GetExternalIdentity returns the link for (provider, subject).
	GetExternalIdentity(provider, subject string) (ExternalIdentity, bool)
	// ListExternalIdentities returns the links belonging to a user.
	ListExternalIdentities(userID tailcfg.UserID) []ExternalIdentity
	// UnlinkExternalIdentity removes a link.
	UnlinkExternalIdentity(provider, subject string) error
}

// AuditStore is the append-only audit log.
type AuditStore interface {
	// AppendAudit appends an event, assigning its ID and time.
	AppendAudit(e *AuditEvent) error
	// ListAudit returns events, oldest first, at most limit of them (0 means
	// no limit).
	ListAudit(limit int) []AuditEvent
}

// WebhookCursorStore tracks how far each webhook endpoint has consumed the
// audit log, so delivery is durable and survives restarts.
//
// Delivery is at-least-once: a crash between a successful POST and the cursor
// update redelivers that event. Receivers deduplicate by the delivery ID in
// the payload.
type WebhookCursorStore interface {
	// ListAuditAfter returns events with ID greater than afterID, oldest
	// first, at most limit of them (0 means no limit).
	ListAuditAfter(afterID uint64, limit int) []AuditEvent
	// GetWebhookCursor returns the last event ID delivered to an endpoint, or
	// 0 when it has never delivered.
	GetWebhookCursor(endpoint string) uint64
	// SetWebhookCursor records the last event ID delivered to an endpoint.
	SetWebhookCursor(endpoint string, eventID uint64) error
}

// Store is the persistence boundary of the trust plane.
type Store interface {
	UserStore
	ExternalIdentityStore
	AuditStore
	WebhookCursorStore
	AuthTransactionStore
	SessionStore
	DeviceAuthorizationStore
	SSHCheckStore
	APIKeyStore
}
