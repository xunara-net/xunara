package identity

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// IdentityProvider authenticates one account and reports who it is.
//
// A provider is deliberately not a session and not a user: it answers "which
// external account is this?" and nothing else. Deciding which user to attach
// the result to, and whether to create a session, belongs to the caller
// (AGENTS.md section 10).
type IdentityProvider interface {
	// ID returns the stable provider identifier used as the identity key's
	// first half.
	ID() string

	// Begin starts an authentication. The transaction already carries the
	// state, nonce and PKCE material to send to the provider.
	//
	// An AuthorizationRequest with an empty URL means the provider needs no
	// browser redirect; the caller must call Callback immediately.
	Begin(ctx context.Context, tx *AuthTransaction) (*AuthorizationRequest, error)

	// Callback validates the provider's answer and returns the authenticated
	// identity. It must verify every security property the provider can offer
	// (state, nonce, PKCE, signature, issuer, audience, expiry) and must fail
	// closed.
	Callback(ctx context.Context, tx *AuthTransaction, req *CallbackRequest) (*IdentityResult, error)
}

// AuthorizationRequest is where the browser must go to authenticate.
type AuthorizationRequest struct {
	// URL is the provider's authorization endpoint, with state, nonce and
	// PKCE attached. Empty means "no redirect needed".
	URL string
}

// CallbackRequest is the provider-agnostic half of a callback: the raw query
// values, so that a provider can read whatever its protocol defines.
type CallbackRequest struct {
	// Code and State are the OAuth authorization code and state.
	Code  string
	State string

	// Error and ErrorDescription carry an authorization error response.
	Error            string
	ErrorDescription string

	// Values is the complete query, for provider-specific parameters.
	Values map[string][]string
}

// Value returns the first value of a query parameter.
func (r *CallbackRequest) Value(key string) string {
	if r == nil {
		return ""
	}
	if vs := r.Values[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Registry maps provider IDs to providers.
//
// It is safe for concurrent use because login handlers read it while
// configuration may still be loading.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]IdentityProvider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]IdentityProvider)}
}

// Register adds a provider, replacing any provider with the same ID.
func (r *Registry) Register(p IdentityProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ID()] = p
}

// Get returns the provider with the given ID.
func (r *Registry) Get(id string) (IdentityProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// IDs returns the registered provider IDs, sorted.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for id := range r.providers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// LocalLogin authenticates the built-in local user (see [LocalProviderID])
// synchronously, without a browser redirect. It must only be enabled when no
// external provider is configured: it trusts anyone who can reach the login
// endpoint.
type LocalLogin struct{}

// ID implements [IdentityProvider].
func (LocalLogin) ID() string { return LocalProviderID }

// Begin implements [IdentityProvider]. The empty URL marks a login that
// completes server-side.
func (LocalLogin) Begin(context.Context, *AuthTransaction) (*AuthorizationRequest, error) {
	return &AuthorizationRequest{}, nil
}

// Callback implements [IdentityProvider]: the local user is always the subject.
func (LocalLogin) Callback(context.Context, *AuthTransaction, *CallbackRequest) (*IdentityResult, error) {
	return &IdentityResult{
		ProviderID:  LocalProviderID,
		Subject:     LocalLoginName,
		DisplayName: LocalDisplayName,
	}, nil
}

// Assert that the local provider satisfies the interface.
var _ IdentityProvider = LocalLogin{}

// AuthTransactionExpired reports whether tx has expired at now.
func (tx AuthTransaction) Expired(now time.Time) bool {
	return !tx.ExpiresAt.IsZero() && now.After(tx.ExpiresAt)
}

// Consumed reports whether tx has already been redeemed.
func (tx AuthTransaction) Consumed() bool { return !tx.ConsumedAt.IsZero() }

// String implements fmt.Stringer without leaking secrets.
func (tx AuthTransaction) String() string {
	return fmt.Sprintf("AuthTransaction{ID:%s Provider:%s ExpiresAt:%s}", tx.ID, tx.ProviderID, tx.ExpiresAt.Format(time.RFC3339))
}
