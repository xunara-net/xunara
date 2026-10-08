package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// base64URL is the unpadded URL-safe encoding every secret uses.
func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newID returns a fresh 128-bit hex identifier with a prefix.
func newID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity: generating an identifier: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// secretBytes is the entropy of every bearer secret this package generates:
// session tokens, OAuth state, nonces, PKCE verifiers and browser cookies.
const secretBytes = 32

// newSecret returns a fresh 256-bit URL-safe secret.
func newSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: generating a secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewSecret returns a fresh URL-safe secret with n bytes of entropy. It is
// exported for the few callers outside this package that need the same quality
// of randomness without re-deriving the encoding rules (the control plane's
// one-time setup token, for example).
func NewSecret(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("identity: secret size must be positive, got %d", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: generating a secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret returns the hex SHA-256 of a bearer secret, the form that is
// stored: a leaked database must not hand out working tokens. Secrets that
// must be reconstructed later (an OAuth state, a PKCE verifier) are stored
// verbatim; those that are only ever compared (session tokens, the browser
// binding of a transaction) are stored hashed.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SecretEqual reports whether secret matches a stored hash, in constant time.
func SecretEqual(storedHash, secret string) bool {
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(HashSecret(secret))) == 1
}

// PKCEPair returns an RFC 7636 code verifier and its S256 challenge.
func PKCEPair() (verifier, challenge string, err error) {
	verifier, err = newSecret()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
