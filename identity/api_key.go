package identity

import (
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// APIKey is a service identity credential: a token an automation holds to call
// the platform API without a browser session.
//
// It is deliberately a separate object from User, Session and Machine: a key
// authenticates a service, never a human, and carries only the scopes it was
// granted (AGENTS.md section 5).
type APIKey struct {
	// ID is the public identifier used for revocation and audit.
	ID string

	// Name describes the automation the key was issued to.
	Name string

	// UserID is the owner the key acts for. The key itself is still a service
	// identity: it never becomes a login method for a human.
	UserID tailcfg.UserID

	// Scopes are the permissions granted to the key ("read", "write").
	Scopes []string

	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// API key scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// APIKeyPrefix marks Xunara API tokens, so secret scanners can find them.
const APIKeyPrefix = "xunara_"

// Errors returned by the API key store.
var (
	// ErrAPIKeyNotFound is returned for an unknown, expired or revoked key.
	// The cases are indistinguishable to callers on purpose.
	ErrAPIKeyNotFound = errors.New("identity: API key not found")
	// ErrAPIKeyRevoked is returned by revocation helpers for a revoked key.
	ErrAPIKeyRevoked = errors.New("identity: API key revoked")
)

// NewAPIKeyOptions are the inputs to [APIKeyStore.CreateAPIKey].
type NewAPIKeyOptions struct {
	Name   string
	UserID tailcfg.UserID
	Scopes []string
	// TTL bounds the key's lifetime. Zero means it never expires.
	TTL time.Duration
}

// HasScope reports whether the key carries the scope.
func (k APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Expired reports whether the key has expired at now.
func (k APIKey) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)
}

// APIKeyStore is the durable service-identity table.
type APIKeyStore interface {
	// CreateAPIKey creates a key and returns its token. Only the token's hash
	// is stored, so the token is returned exactly once.
	CreateAPIKey(opts NewAPIKeyOptions) (APIKey, string, error)

	// GetAPIKeyByToken resolves a token to a live key. Unknown, expired and
	// revoked keys all return ErrAPIKeyNotFound.
	GetAPIKeyByToken(token string) (APIKey, error)

	// GetAPIKeyByID returns a key by its public ID, including expired and
	// revoked ones, for administration.
	GetAPIKeyByID(id string) (APIKey, bool)

	// ListAPIKeys returns every key, newest first.
	ListAPIKeys() []APIKey

	// TouchAPIKey records the key's last use.
	TouchAPIKey(id string, now time.Time) error

	// RevokeAPIKey revokes a key. Revoking an already-revoked key is a no-op.
	RevokeAPIKey(id string) error
}
