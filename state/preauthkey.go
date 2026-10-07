package state

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// preAuthKeyPrefix mirrors the prefix Tailscale uses for pre-authentication
// keys.
//
// The literal shape matters for security, not just familiarity: official
// clients redact secrets matching `tskey-[A-Za-z0-9-]+` from their logs
// (see cmd/tailscale/cli/cli.go in the upstream tree). A key that did not match
// would be printed verbatim in user-visible output.
const preAuthKeyPrefix = "tskey-auth-"

// preAuthKeySecretChars is the number of random characters in a key secret.
// base32 without padding yields 5 bits per character, so 26 characters is 130
// bits of entropy.
const preAuthKeySecretChars = 26

// preAuthKeyEncoding is base32 without padding: the output alphabet is
// A-Z and 2-7, which stays inside the `[A-Za-z0-9-]+` redaction pattern.
var preAuthKeyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// PreAuthKey authorizes a node without an interactive login.
//
// A pre-auth key is a machine-authorization credential: it never becomes a
// human identity, and the node it registers is still tracked separately from
// any user session (AGENTS.md section 5).
type PreAuthKey struct {
	// ID is the server-local identifier.
	ID uint64

	// Key is the secret presented by clients.
	Key string

	// UserID is the user the authorized node belongs to.
	UserID tailcfg.UserID

	// Reusable allows the key to authorize more than one node.
	Reusable bool

	// Ephemeral marks nodes authorized by this key for reaping once inactive.
	Ephemeral bool

	// Used reports whether the key has authorized at least one node.
	Used bool

	// Expiry is when the key stops working. The zero value never expires.
	Expiry time.Time

	// Created is when the key was created.
	Created time.Time

	// UsedAt is when the key last authorized a node.
	UsedAt *time.Time
}

// Usable reports whether the key may authorize a node at time now.
func (k PreAuthKey) Usable(now time.Time) bool {
	if !k.Expiry.IsZero() && k.Expiry.Before(now) {
		return false
	}
	if k.Used && !k.Reusable {
		return false
	}
	return true
}

// NewPreAuthKeySecret returns a fresh pre-authentication key secret.
func NewPreAuthKeySecret() (string, error) {
	buf := make([]byte, preAuthKeySecretChars)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	// Base32 output is uppercase; lowercase it so keys are uniform and easy to
	// copy without case confusion.
	encoded := strings.ToLower(preAuthKeyEncoding.EncodeToString(buf))[:preAuthKeySecretChars]

	return preAuthKeyPrefix + encoded, nil
}

// IsPreAuthKeySecret reports whether s has the shape of a pre-auth key secret.
func IsPreAuthKeySecret(s string) bool {
	return strings.HasPrefix(s, preAuthKeyPrefix)
}

// Errors returned by the pre-auth key store methods.
var (
	errPreAuthKeyRequired = errors.New("state: pre-auth key secret is required")
	errPreAuthKeyNotFound = errors.New("state: pre-auth key not found")
)
