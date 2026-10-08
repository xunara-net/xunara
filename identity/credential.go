package identity

import (
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// ErrCredentialNotFound is returned when a user has no local password.
var ErrCredentialNotFound = errors.New("identity: no local credential for user")

// LocalCredential is the password of a locally managed user.
//
// The credential is keyed by user ID, not by login name: renaming a user must
// not orphan or reassign a password. A user without a credential simply
// cannot sign in with a password (they may still sign in through an identity
// provider or a passkey).
type LocalCredential struct {
	UserID       tailcfg.UserID
	PasswordHash []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LocalCredentialStore stores local passwords.
type LocalCredentialStore interface {
	// SetLocalCredential stores or replaces the password of a user.
	SetLocalCredential(c *LocalCredential) error
	// GetLocalCredential returns the credential of a user.
	GetLocalCredential(userID tailcfg.UserID) (LocalCredential, bool)
	// DeleteLocalCredential removes it; a missing credential is not an error.
	DeleteLocalCredential(userID tailcfg.UserID) error
	// CountLocalCredentials reports how many users can sign in with a
	// password, which is how first-run setup decides whether an
	// administrator already exists.
	CountLocalCredentials() int
}
