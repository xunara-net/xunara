package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Anonymous forms (sign in, first-run setup, registration) have no session to
// bind a CSRF token to, so they carry a signed token instead: it names the
// form it was minted for and expires, and the signing key never leaves the
// server. Without it, a page on another site could submit the sign-in form
// with the attacker's credentials and silently log the victim into the wrong
// account.

// formTokenTTL bounds how long a rendered page's token stays valid. Long
// enough for a form left open while the operator finds the setup token, short
// enough that a leaked token ages out.
const formTokenTTL = 45 * time.Minute

// formKeyFile holds the per-deployment signing key. It is generated on first
// start and kept with the rest of the state, so tokens survive a restart.
const formKeyFile = "form.key"

// loadOrCreateFormKey returns the deployment's form-signing key.
func loadOrCreateFormKey(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, formKeyFile)
	if key, err := os.ReadFile(path); err == nil && len(key) == 32 {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// newFormToken mints a token for one form.
func (s *Server) newFormToken(purpose string) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		// A token that cannot be random must not be usable; the form will
		// fail CSRF rather than accept a guessable value.
		s.log.Error("generating form token", "err", err)
		return ""
	}

	issued := make([]byte, 8)
	binary.BigEndian.PutUint64(issued, uint64(time.Now().Unix()))

	mac := hmac.New(sha256.New, s.formKey)
	mac.Write([]byte(purpose))
	mac.Write(nonce)
	mac.Write(issued)
	sum := mac.Sum(nil)[:16]

	return base64.RawURLEncoding.EncodeToString(append(append(nonce, issued...), sum...))
}

// checkFormToken verifies a token minted by [Server.newFormToken] for the
// same purpose and within its lifetime.
func (s *Server) checkFormToken(purpose, token string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 16+8+16 {
		return false
	}
	nonce, issued, sum := raw[:16], raw[16:24], raw[24:]

	at := time.Unix(int64(binary.BigEndian.Uint64(issued)), 0)
	if at.After(now.Add(time.Minute)) || now.Sub(at) > formTokenTTL {
		return false
	}

	mac := hmac.New(sha256.New, s.formKey)
	mac.Write([]byte(purpose))
	mac.Write(nonce)
	mac.Write(issued)
	return hmac.Equal(mac.Sum(nil)[:16], sum)
}

// clientIP is the address a request came from. It deliberately ignores
// X-Forwarded-For: rate limits must key on something an anonymous caller
// cannot choose, and a deployment behind a proxy would otherwise let anyone
// rotate the header to bypass the limit.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
