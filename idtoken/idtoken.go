// Package idtoken issues the OIDC ID tokens a Tailscale node fetches from its
// control plane (POST /machine/id-token) so workloads can prove their tailnet
// identity to a third party that trusts the control plane's issuer
// (tailcfg.TokenResponse documents the claim set).
//
// This package owns the signing half: a small RSA keyring in the state
// directory, the JWKS a relying party fetches, and rotation. The claims
// themselves belong to the control plane, which knows the netmap.
//
// Security properties (AGENTS.md section 8):
//
//   - The keyring file is created 0600 and never leaves the state directory; a
//     file readable by anyone else is refused rather than used.
//   - Keys are generated lazily, so a deployment that never issues an identity
//     token never creates one.
//   - Rotation retires the active key instead of deleting it: the retired
//     public key stays in the JWKS until every token it signed has expired
//     (plus clock-skew slack), so a relying party that has not refreshed the
//     JWKS yet still verifies tokens minted before the rotation. Expired keys
//     are dropped the next time the keyring is read, so the JWKS cannot grow
//     without bound.
//   - The keyring is re-read on every use, so an operator running
//     `xunara id-token rotate` next to a live server takes effect immediately.
package idtoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// KeyFileName is the keyring file inside the control plane's state
	// directory.
	KeyFileName = "id_token_keys.json"

	// keyBits is the RSA key size. 2048 is the floor every OIDC relying party
	// accepts; identity tokens are short-lived, so the extra cost of a larger
	// key buys nothing here.
	keyBits = 2048

	// TTL is how long an issued ID token is valid. Tokens are bearer
	// credentials for a third party: keep them short.
	TTL = 15 * time.Minute

	// KeyGrace is how long a retired key keeps being published in the JWKS
	// after it stopped signing. It must exceed TTL (tokens minted just before
	// the rotation are still valid) plus slack for a relying party's clock
	// skew and JWKS cache.
	KeyGrace = TTL + 5*time.Minute

	// Algorithm is the JWS algorithm of every token this issuer signs.
	Algorithm = "RS256"

	// keyFileVersion is the on-disk format version.
	keyFileVersion = 1
)

// SigningPublicKeyAlgorithm mirrors Algorithm for callers that need the
// crypto.SignatureAlgorithm value (tests verifying a token).
const SigningPublicKeyAlgorithm = jose.RS256

// errKeyringPermissions marks a keyring whose file is readable by users other
// than its owner. Unlike a parse error this is never tolerated: publishing (or
// signing with) a private key on a shared-readable file is a deployment defect
// an operator must fix.
var errKeyringPermissions = errors.New("idtoken: keyring file is readable beyond its owner")

// Keyring is a lazily loaded set of signing keys for one state directory.
//
// It is safe for concurrent use.
type Keyring struct {
	mu  sync.Mutex
	dir string
	log *slog.Logger

	// keys is the in-memory view, newest last. A key with a zero retired time
	// is active and is the one used for signing.
	keys []signingKey
}

type signingKey struct {
	kid     string
	created time.Time
	retired time.Time // zero: active
	priv    *rsa.PrivateKey
}

// NewKeyring returns a keyring rooted at the control plane's state directory.
// Nothing is read or written until the keyring is used.
func NewKeyring(stateDir string, log *slog.Logger) *Keyring {
	return &Keyring{dir: stateDir, log: log}
}

// Sign returns a compact JWS for the given claims, signed with the active key.
//
// claims is encoded as the JWT payload; callers pass a struct with JSON tags
// (embedding jwt.Claims for the registered ones).
func (k *Keyring) Sign(now time.Time, claims any) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	active, err := k.activeLocked(now)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       jose.JSONWebKey{Key: active.priv, KeyID: active.kid},
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("idtoken: building signer: %w", err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("idtoken: signing token: %w", err)
	}
	return token, nil
}

// ActiveKeyID returns the kid of the key currently used for signing, creating
// the keyring if necessary.
func (k *Keyring) ActiveKeyID(now time.Time) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	active, err := k.activeLocked(now)
	if err != nil {
		return "", err
	}
	return active.kid, nil
}

// KeyInfo describes one key in the keyring for administrative output. It
// carries no private material.
type KeyInfo struct {
	KID     string    `json:"kid"`
	Created time.Time `json:"created"`
	// Retired is when the key stopped signing; the zero value means it is the
	// active key.
	Retired time.Time `json:"retired,omitzero"`
}

// Active reports whether the key is the one new tokens are signed with.
func (i KeyInfo) Active() bool { return i.Retired.IsZero() }

// Keys returns the keys currently published in the JWKS, newest last,
// creating the keyring if necessary.
func (k *Keyring) Keys(now time.Time) ([]KeyInfo, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := k.ensureLocked(now); err != nil {
		return nil, err
	}
	infos := make([]KeyInfo, 0, len(k.keys))
	for _, key := range k.keys {
		infos = append(infos, KeyInfo{KID: key.kid, Created: key.created, Retired: key.retired})
	}
	return infos, nil
}

// JWKS returns the public keys a relying party verifies tokens with: the
// active key plus every key retired within KeyGrace.
func (k *Keyring) JWKS(now time.Time) (jose.JSONWebKeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := k.ensureLocked(now); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(k.keys))}
	for _, key := range k.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       key.priv.Public(),
			KeyID:     key.kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	return set, nil
}

// Rotate retires the active key and generates a new one, returning its kid.
//
// The retired key stays in the JWKS for KeyGrace so tokens that were already
// issued keep verifying. Rotation is an administrative action (the CLI runs
// it); a running server adopts the rewritten keyring on its next use.
func (k *Keyring) Rotate(now time.Time) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Adopt whatever is on disk first: another instance may have rotated
	// already, and retiring a key that is not in the file would drop it from
	// the JWKS while its tokens are still alive.
	if err := k.loadLocked(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if len(k.keys) == 0 {
		if err := k.ensureLocked(now); err != nil {
			return "", err
		}
	}

	for i := range k.keys {
		if k.keys[i].retired.IsZero() {
			k.keys[i].retired = now
		}
	}
	fresh, err := generateKey(now)
	if err != nil {
		return "", err
	}
	k.keys = append(k.keys, fresh)
	k.pruneLocked(now)
	if err := k.saveLocked(); err != nil {
		return "", err
	}
	return fresh.kid, nil
}

// activeLocked returns the signing key, loading or creating the keyring first.
// The caller holds mu.
func (k *Keyring) activeLocked(now time.Time) (signingKey, error) {
	if err := k.ensureLocked(now); err != nil {
		return signingKey{}, err
	}
	for i := len(k.keys) - 1; i >= 0; i-- {
		if k.keys[i].retired.IsZero() {
			return k.keys[i], nil
		}
	}
	return signingKey{}, errors.New("idtoken: keyring has no active key")
}

// ensureLocked re-reads the keyring from disk, creating it on first use. The
// caller holds mu.
//
// A keyring that cannot be parsed is not fatal while keys are already loaded:
// the process keeps signing with the keys it has (they were valid when they
// were read) rather than failing every request. A malformed file and no loaded
// keys is an error.
func (k *Keyring) ensureLocked(now time.Time) error {
	if k.dir == "" {
		return errors.New("idtoken: no state directory")
	}
	err := k.loadLocked()
	switch {
	case err == nil:
		// Dropping keys whose tokens have all expired keeps the published JWKS
		// minimal; the write only happens when there is something to drop.
		if k.pruneLocked(now) {
			if err := k.saveLocked(); err != nil {
				k.warn("could not write back the pruned identity-token keyring", "err", err)
			}
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return k.createLocked(now)
	case errors.Is(err, errKeyringPermissions):
		return err
	default:
		if len(k.keys) > 0 {
			k.warn("keeping the loaded identity-token keys", "err", err)
			return nil
		}
		return err
	}
}

// path returns the keyring file path.
func (k *Keyring) path() string { return filepath.Join(k.dir, KeyFileName) }

// loadLocked reads and parses the keyring file, replacing the in-memory view.
// The caller holds mu.
func (k *Keyring) loadLocked() error {
	raw, err := os.ReadFile(k.path())
	if err != nil {
		return err
	}
	if fi, err := os.Stat(k.path()); err == nil && fi.Mode().Perm()&0o077 != 0 {
		// A private key file readable by anyone else is a deployment mistake
		// that must not be papered over.
		return fmt.Errorf("%w: %s has mode %s", errKeyringPermissions, k.path(), fi.Mode().Perm())
	}

	var file keyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("idtoken: parsing %s: %w", k.path(), err)
	}
	if file.Version != keyFileVersion {
		return fmt.Errorf("idtoken: %s has unsupported version %d", k.path(), file.Version)
	}

	keys := make([]signingKey, 0, len(file.Keys))
	for _, entry := range file.Keys {
		parsed, err := entry.parse()
		if err != nil {
			return fmt.Errorf("idtoken: %s: %w", k.path(), err)
		}
		keys = append(keys, parsed)
	}
	k.keys = keys
	return nil
}

// createLocked generates the first key and persists the keyring. The caller
// holds mu.
func (k *Keyring) createLocked(now time.Time) error {
	fresh, err := generateKey(now)
	if err != nil {
		return err
	}
	k.keys = []signingKey{fresh}
	if err := k.saveLocked(); err != nil {
		k.keys = nil
		return err
	}
	return nil
}

// saveLocked writes the keyring atomically (temp file + rename), 0600. The
// caller holds mu.
func (k *Keyring) saveLocked() error {
	file := keyFile{Version: keyFileVersion, Keys: make([]keyEntry, 0, len(k.keys))}
	for _, key := range k.keys {
		file.Keys = append(file.Keys, key.entry())
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("idtoken: encoding keyring: %w", err)
	}
	raw = append(raw, '\n')

	tmp, err := os.CreateTemp(k.dir, ".id_token_keys-*.json")
	if err != nil {
		return fmt.Errorf("idtoken: creating keyring: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("idtoken: setting keyring permissions: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("idtoken: writing keyring: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("idtoken: writing keyring: %w", err)
	}
	if err := os.Rename(tmpName, k.path()); err != nil {
		return fmt.Errorf("idtoken: replacing keyring: %w", err)
	}
	return nil
}

// pruneLocked drops retired keys whose tokens have all expired, reporting
// whether anything was dropped. The caller holds mu.
func (k *Keyring) pruneLocked(now time.Time) bool {
	before := len(k.keys)
	kept := k.keys[:0]
	for _, key := range k.keys {
		if !key.retired.IsZero() && now.After(key.retired.Add(KeyGrace)) {
			continue
		}
		kept = append(kept, key)
	}
	k.keys = kept
	return len(k.keys) != before
}

func (k *Keyring) warn(msg string, args ...any) {
	if k.log != nil {
		k.log.Warn(msg, args...)
	}
}

// keyFile is the on-disk keyring.
type keyFile struct {
	Version int        `json:"version"`
	Keys    []keyEntry `json:"keys"`
}

// keyEntry is one key as stored: the private key in PKCS#8 PEM, plus the
// bookkeeping a rotation needs.
type keyEntry struct {
	KID           string     `json:"kid"`
	Created       time.Time  `json:"created"`
	Retired       *time.Time `json:"retired,omitempty"`
	PrivateKeyPEM string     `json:"privateKeyPEM"`
}

func (e keyEntry) parse() (signingKey, error) {
	block, _ := pem.Decode([]byte(e.PrivateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		return signingKey{}, fmt.Errorf("key %s is not a PKCS#8 PEM private key", e.KID)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return signingKey{}, fmt.Errorf("key %s: %w", e.KID, err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return signingKey{}, fmt.Errorf("key %s is a %T, not an RSA key", e.KID, parsed)
	}
	if err := priv.Validate(); err != nil {
		return signingKey{}, fmt.Errorf("key %s: %w", e.KID, err)
	}
	// The kid is derived from the public key, so a hand-edited file cannot
	// make two keys claim the same identity.
	kid, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return signingKey{}, err
	}
	if e.KID != "" && e.KID != kid {
		return signingKey{}, fmt.Errorf("key %s does not match its public key (want %s)", e.KID, kid)
	}
	key := signingKey{kid: kid, created: e.Created, priv: priv}
	if e.Retired != nil {
		key.retired = *e.Retired
	}
	return key, nil
}

func (k signingKey) entry() keyEntry {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		// Marshalling a key we generated cannot fail; report loudly if it ever
		// does rather than writing a truncated keyring.
		panic(fmt.Sprintf("idtoken: marshalling private key: %v", err))
	}
	entry := keyEntry{
		KID:           k.kid,
		Created:       k.created,
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
	if !k.retired.IsZero() {
		retired := k.retired
		entry.Retired = &retired
	}
	return entry
}

// generateKey creates a fresh signing key.
func generateKey(now time.Time) (signingKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return signingKey{}, fmt.Errorf("idtoken: generating RSA key: %w", err)
	}
	kid, err := thumbprint(&priv.PublicKey)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{kid: kid, created: now.UTC(), priv: priv}, nil
}

// thumbprint returns the RFC 7638 JWK thumbprint of a public key, base64url
// encoded: the standard, collision-free way to name a key.
func thumbprint(pub *rsa.PublicKey) (string, error) {
	key := jose.JSONWebKey{Key: pub}
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("idtoken: computing key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// TrimIssuer normalises a server URL for use as an issuer identifier: no
// trailing slash (the issuer must match the URL a relying party configures).
func TrimIssuer(serverURL string) string {
	return strings.TrimRight(serverURL, "/")
}
