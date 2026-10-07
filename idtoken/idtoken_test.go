package idtoken

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testClaims is a minimal claim set with one registered and one private claim.
type testClaims struct {
	jwt.Claims
	Key string `json:"key"`
}

// now returns a fixed instant so key lifetimes in tests are exact.
func now() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }

func newTestKeyring(t *testing.T) (*Keyring, string) {
	t.Helper()

	dir := t.TempDir()
	return NewKeyring(dir, nil), dir
}

func TestKeyringCreatesPrivateFileOnFirstUse(t *testing.T) {
	kr, dir := newTestKeyring(t)

	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); !os.IsNotExist(err) {
		t.Fatalf("keyring file exists before first use (err = %v)", err)
	}

	kid, err := kr.ActiveKeyID(now())
	if err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}
	if kid == "" {
		t.Fatal("active kid is empty")
	}

	path := filepath.Join(dir, KeyFileName)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat keyring: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("keyring mode = %s, want 0600", got)
	}

	// The file holds exactly one active key, and no stray temporary files are
	// left behind by the atomic write.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading keyring: %v", err)
	}
	var file keyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing keyring: %v", err)
	}
	if file.Version != keyFileVersion || len(file.Keys) != 1 {
		t.Fatalf("keyring = %+v, want version %d with one key", file, keyFileVersion)
	}
	if file.Keys[0].KID != kid || file.Keys[0].Retired != nil {
		t.Errorf("stored key = %+v, want active key %s", file.Keys[0], kid)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading state dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("state dir holds %d files, want only the keyring", len(entries))
	}
}

func TestSignRoundTripsThroughJWKS(t *testing.T) {
	kr, _ := newTestKeyring(t)

	claims := testClaims{
		Claims: jwt.Claims{
			Audience: jwt.Audience{"https://api.example.com"},
			Expiry:   jwt.NewNumericDate(now().Add(TTL)),
			IssuedAt: jwt.NewNumericDate(now()),
			Issuer:   "https://login.example.com",
			ID:       "jti-1",
			Subject:  "node.example.com.",
		},
		Key: "nodekey:abc",
	}
	token, err := kr.Sign(now(), claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	set, err := kr.JWKS(now())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	activeKID, err := kr.ActiveKeyID(now())
	if err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	if got := parsed.Headers[0].KeyID; got != activeKID {
		t.Errorf("token kid = %q, want the active kid %q", got, activeKID)
	}
	if got := parsed.Headers[0].Algorithm; got != Algorithm {
		t.Errorf("token alg = %q, want %s", got, Algorithm)
	}

	keys := set.Key(activeKID)
	if len(keys) != 1 {
		t.Fatalf("JWKS holds %d keys for %q, want 1", len(keys), activeKID)
	}
	var decoded testClaims
	if err := parsed.Claims(keys[0].Key, &decoded); err != nil {
		t.Fatalf("verifying token: %v", err)
	}
	if decoded.Subject != claims.Subject || decoded.Key != claims.Key || decoded.ID != claims.ID {
		t.Errorf("verified claims = %+v, want %+v", decoded, claims)
	}
	if !decoded.Expiry.Time().Equal(claims.Expiry.Time()) {
		t.Errorf("exp = %v, want %v", decoded.Expiry.Time(), claims.Expiry.Time())
	}
}

func TestRotateKeepsRetiredKeyUntilTokensExpire(t *testing.T) {
	kr, _ := newTestKeyring(t)

	first, err := kr.ActiveKeyID(now())
	if err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}
	token, err := kr.Sign(now(), jwt.Claims{
		Audience: jwt.Audience{"https://api.example.com"},
		Expiry:   jwt.NewNumericDate(now().Add(TTL)),
		IssuedAt: jwt.NewNumericDate(now()),
		Subject:  "node.example.com.",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rotatedAt := now().Add(time.Minute)
	second, err := kr.Rotate(rotatedAt)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if second == first {
		t.Fatal("rotation reused the previous key")
	}

	// A relying party that has not refreshed the JWKS must still be able to
	// verify a token minted before the rotation.
	set, err := kr.JWKS(rotatedAt.Add(time.Second))
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS holds %d keys after rotation, want 2", len(set.Keys))
	}
	if keys := set.Key(first); len(keys) != 1 {
		t.Fatalf("retired key %q is not published", first)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	if err := parsed.Claims(set.Key(first)[0].Key, &jwt.Claims{}); err != nil {
		t.Errorf("token minted before the rotation no longer verifies: %v", err)
	}

	// New tokens use the new key.
	newToken, err := kr.Sign(rotatedAt.Add(time.Second), jwt.Claims{Subject: "node.example.com."})
	if err != nil {
		t.Fatalf("Sign after rotation: %v", err)
	}
	parsed, err = jwt.ParseSigned(newToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing new token: %v", err)
	}
	if got := parsed.Headers[0].KeyID; got != second {
		t.Errorf("new token kid = %q, want %q", got, second)
	}

	// Once every token the old key signed has expired (plus the grace period
	// for clock skew and JWKS caches), reading the keyring drops it — without
	// another rotation — and the file no longer holds the private key.
	after := rotatedAt.Add(KeyGrace + time.Minute)
	set, err = kr.JWKS(after)
	if err != nil {
		t.Fatalf("JWKS after grace: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != second {
		t.Fatalf("JWKS after grace = %+v, want only %q", set.Keys, second)
	}
	raw, err := os.ReadFile(filepath.Join(kr.dir, KeyFileName))
	if err != nil {
		t.Fatalf("reading keyring: %v", err)
	}
	if strings.Contains(string(raw), first) {
		t.Error("pruned key is still present in the keyring file")
	}
	if !strings.Contains(string(raw), second) {
		t.Error("active key is missing from the keyring file")
	}
}

func TestKeysReportsActiveAndRetired(t *testing.T) {
	kr, _ := newTestKeyring(t)

	first, err := kr.ActiveKeyID(now())
	if err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}
	second, err := kr.Rotate(now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	keys, err := kr.Keys(now().Add(2 * time.Minute))
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Keys returned %d entries, want 2", len(keys))
	}
	if keys[0].KID != first || keys[0].Active() {
		t.Errorf("first key = %+v, want retired %s", keys[0], first)
	}
	if keys[1].KID != second || !keys[1].Active() {
		t.Errorf("second key = %+v, want active %s", keys[1], second)
	}
	if keys[0].Retired.IsZero() || keys[0].Created.IsZero() {
		t.Errorf("retired key has no timestamps: %+v", keys[0])
	}
}

func TestKeyringRefusesGroupReadableFile(t *testing.T) {
	kr, dir := newTestKeyring(t)
	if _, err := kr.ActiveKeyID(now()); err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}

	path := filepath.Join(dir, KeyFileName)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// A fresh keyring is what a new process sees: the misconfiguration must be
	// an error, not a warning.
	fresh := NewKeyring(dir, nil)
	if _, err := fresh.JWKS(now()); err == nil {
		t.Fatal("JWKS accepted a keyring readable beyond its owner")
	} else if !strings.Contains(err.Error(), "readable beyond its owner") {
		t.Errorf("error = %v, want a permissions complaint", err)
	}
	if _, err := fresh.Sign(now(), jwt.Claims{Subject: "node.example.com."}); err == nil {
		t.Fatal("Sign accepted a keyring readable beyond its owner")
	}
}

func TestKeyringRejectsWrongVersionAndBadKeys(t *testing.T) {
	for name, content := range map[string]string{
		"wrong version": `{"version":99,"keys":[]}`,
		"no keys":       `{"version":1,"keys":[{"kid":"x","privateKeyPEM":"not a pem"}]}`,
		"mismatched kid": `{"version":1,"keys":[{"kid":"not-the-thumbprint","privateKeyPEM":` +
			jsonString(testPrivatePEM(t)) + `}]}`,
		"not json": `{`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, KeyFileName)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("%s: writing keyring: %v", name, err)
		}
		if _, err := NewKeyring(dir, nil).JWKS(now()); err == nil {
			t.Errorf("%s: JWKS accepted a broken keyring", name)
		}
	}
}

// testPrivatePEM generates a key and returns its PKCS#8 PEM, for tests that
// need key material without going through the keyring.
func testPrivatePEM(t *testing.T) string {
	t.Helper()

	key, err := generateKey(now())
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	return key.entry().PrivateKeyPEM
}

// jsonString encodes s as a JSON string.
func jsonString(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
