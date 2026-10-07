package identity

// This file holds the WebAuthn (passkey) half of the trust plane: the
// persisted credentials and the single-use ceremonies that carry a challenge
// from the browser's HTTP request to its response.
//
// A passkey is a Human Identity credential (AGENTS.md section 5): it signs a
// user in, and it never authorizes a machine. Ceremonies are their own object,
// separate from AuthTransaction, Session and DeviceAuthorization (section 10):
// they carry a challenge and the library's session state, not an OAuth
// redirect.

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"tailscale.com/tailcfg"
)

// DefaultPasskeyCeremonyTTL bounds how long a started ceremony may be
// finished. WebAuthn challenges are answered by the authenticator within
// seconds; minutes of slack cover a slow user gesture.
const DefaultPasskeyCeremonyTTL = 5 * time.Minute

var (
	// ErrPasskeyNotFound is returned when a passkey row does not resolve.
	ErrPasskeyNotFound = errors.New("identity: passkey not found")
	// ErrPasskeyCeremonyNotFound is returned when a ceremony ID does not
	// exist (or never did).
	ErrPasskeyCeremonyNotFound = errors.New("identity: passkey ceremony not found")
	// ErrPasskeyCeremonyConsumed is returned when a ceremony was already
	// finished: challenges are single-use (AGENTS.md section 7, replay).
	ErrPasskeyCeremonyConsumed = errors.New("identity: passkey ceremony already used")
	// ErrPasskeyCeremonyExpired is returned when a ceremony passed its TTL.
	ErrPasskeyCeremonyExpired = errors.New("identity: passkey ceremony expired")
)

// Passkey is one registered WebAuthn credential. The stored credential holds
// public-key material and the authenticator's counters; a private key never
// leaves the authenticator.
type Passkey struct {
	ID     string
	UserID tailcfg.UserID
	// Name is a user-chosen label ("MacBook Touch ID"), never an identity.
	Name string
	// CredentialID is the authenticator's credential ID (the WebAuthn raw
	// ID), unique across all users.
	CredentialID []byte
	Credential   webauthn.Credential
	CreatedAt    time.Time
	// LastUsedAt is zero until the passkey has signed someone in.
	LastUsedAt time.Time
}

// PasskeyStore is the WebAuthn credential half of the trust plane.
type PasskeyStore interface {
	// CreatePasskey stores a registered passkey. It fails if the credential
	// ID is already registered (to anyone).
	CreatePasskey(p *Passkey) error
	// ListPasskeys returns a user's passkeys, oldest first.
	ListPasskeys(userID tailcfg.UserID) []Passkey
	// GetPasskeyByCredentialID resolves the credential ID an authenticator
	// presented in an assertion.
	GetPasskeyByCredentialID(credentialID []byte) (Passkey, bool)
	// UpdatePasskey records the post-assertion state: the authenticator's
	// sign counter (clone detection) and when the passkey was last used.
	UpdatePasskey(id string, credential webauthn.Credential, usedAt time.Time) error
	// DeletePasskey removes one passkey owned by userID. It fails with
	// ErrPasskeyNotFound when the passkey does not exist or belongs to
	// someone else, so IDs cannot probe other accounts.
	DeletePasskey(id string, userID tailcfg.UserID) error
}

// PasskeyCeremonyKind distinguishes what a ceremony is for.
type PasskeyCeremonyKind string

const (
	// PasskeyCeremonyRegister creates a passkey for a signed-in user.
	PasskeyCeremonyRegister PasskeyCeremonyKind = "register"
	// PasskeyCeremonyLogin signs a user in, usernameless: the authenticator
	// picks the discoverable credential and the server learns the account
	// from the user handle.
	PasskeyCeremonyLogin PasskeyCeremonyKind = "login"
)

// Valid reports whether the kind is one this build knows.
func (k PasskeyCeremonyKind) Valid() bool {
	return k == PasskeyCeremonyRegister || k == PasskeyCeremonyLogin
}

// PasskeyCeremony carries one in-flight WebAuthn ceremony. It is persisted, so
// any control-plane instance can finish what another started, and single-use,
// so a captured response cannot be replayed.
type PasskeyCeremony struct {
	ID   string
	Kind PasskeyCeremonyKind
	// UserID is the account a registration belongs to. It is zero for a
	// usernameless login ceremony.
	UserID tailcfg.UserID
	// Session is the library's ceremony state (challenge, expiry, allowed
	// credentials), stored verbatim: it is not a bearer secret, but it must
	// match the browser that began the ceremony.
	Session []byte
	// BrowserSessionHash is the hash of a random cookie value set when the
	// ceremony began; the finish request must present the same value.
	BrowserSessionHash string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	ConsumedAt         time.Time
}

// Expired reports whether the ceremony's TTL has passed at now.
func (c PasskeyCeremony) Expired(now time.Time) bool { return !now.Before(c.ExpiresAt) }

// Consumed reports whether the ceremony was already finished.
func (c PasskeyCeremony) Consumed() bool { return !c.ConsumedAt.IsZero() }

// NewPasskeyCeremonyOptions are the inputs to [PasskeyCeremonyStore.CreatePasskeyCeremony].
type NewPasskeyCeremonyOptions struct {
	Kind PasskeyCeremonyKind
	// UserID is required for registration and must be zero for a usernameless
	// login.
	UserID  tailcfg.UserID
	Session []byte
	// ExpiresAt comes from the library's session data; zero applies
	// [DefaultPasskeyCeremonyTTL].
	ExpiresAt time.Time
}

// PasskeyCeremonyStore persists in-flight WebAuthn ceremonies.
type PasskeyCeremonyStore interface {
	// CreatePasskeyCeremony stores a ceremony and returns it together with
	// the browser secret whose hash it recorded. The caller sets the secret
	// as an HttpOnly cookie.
	CreatePasskeyCeremony(opts NewPasskeyCeremonyOptions) (PasskeyCeremony, string, error)
	// GetPasskeyCeremony returns a ceremony by ID.
	GetPasskeyCeremony(id string) (PasskeyCeremony, bool)
	// ConsumePasskeyCeremony atomically marks a ceremony finished. It returns
	// ErrPasskeyCeremonyNotFound, ErrPasskeyCeremonyConsumed or
	// ErrPasskeyCeremonyExpired instead of a ceremony the caller may not use.
	ConsumePasskeyCeremony(id string) (PasskeyCeremony, error)
	// DeleteExpiredPasskeyCeremonies removes ceremonies past their expiry and
	// reports how many were deleted.
	DeleteExpiredPasskeyCeremonies(now time.Time) (int64, error)
}
