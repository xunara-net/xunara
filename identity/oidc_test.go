package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIDP is a minimal OIDC issuer for tests: discovery, JWKS rotation and a
// token endpoint that enforces PKCE and mints signed ID tokens.
type fakeIDP struct {
	server *httptest.Server
	issuer string

	mu        sync.Mutex
	key       *rsa.PrivateKey
	kid       string
	otherKey  *rsa.PrivateKey
	usedCodes map[string]bool
	codeSeq   int

	// wantChallenge is the PKCE challenge the token endpoint accepts.
	wantChallenge string
	// mint describes the ID token the token endpoint returns.
	mint mintOptions
}

// mintOptions override what the token endpoint signs.
type mintOptions struct {
	subject  string
	nonce    string
	email    string
	name     string
	issuer   string
	audience string
	expiry   time.Time
	issuedAt time.Time
	signKey  *rsa.PrivateKey
	signKID  string
	noToken  bool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	f := &fakeIDP{key: key, kid: "key-1", otherKey: other, usedCodes: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/keys", f.handleKeys)
	mux.HandleFunc("/token", f.handleToken)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	f.issuer = f.server.URL
	return f
}

// freshCode returns an unredeemed authorization code.
func (f *fakeIDP) freshCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codeSeq++
	return fmt.Sprintf("code-%d", f.codeSeq)
}

func (f *fakeIDP) rotateKeys(key *rsa.PrivateKey, kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key, f.kid = key, kid
}

func (f *fakeIDP) setMint(m mintOptions) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mint = m
}

func (f *fakeIDP) setChallenge(challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wantChallenge = challenge
}

func (f *fakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeTestJSON(w, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/auth",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIDP) handleKeys(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	key, kid := f.key, f.kid
	f.mu.Unlock()

	pub := key.Public().(*rsa.PublicKey)
	writeTestJSON(w, map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (f *fakeIDP) handleToken(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if got := req.PostForm.Get("grant_type"); got != "authorization_code" {
		writeTestJSON(w, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	code := req.PostForm.Get("code")

	f.mu.Lock()
	challengeOK := f.wantChallenge != "" &&
		PKCEChallenge(req.PostForm.Get("code_verifier")) == f.wantChallenge
	replayed := f.usedCodes[code]
	if !replayed {
		f.usedCodes[code] = true
	}
	mint := f.mint
	key, kid := f.key, f.kid
	f.mu.Unlock()

	if replayed {
		writeTestJSON(w, map[string]any{"error": "invalid_grant", "error_description": "code already used"})
		return
	}
	if !challengeOK {
		writeTestJSON(w, map[string]any{"error": "invalid_grant", "error_description": "pkce mismatch"})
		return
	}
	if mint.noToken {
		writeTestJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer"})
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss": pick(mint.issuer, f.issuer),
		"aud": pick(mint.audience, "client-1"),
		"sub": pick(mint.subject, "sub-1"),
		"iat": mint.issuedAt.Unix(),
		"exp": mint.expiry.Unix(),
	}
	if mint.issuedAt.IsZero() {
		claims["iat"] = now.Unix()
	}
	if mint.expiry.IsZero() {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	if mint.nonce != "" {
		claims["nonce"] = mint.nonce
	}
	if mint.email != "" {
		claims["email"] = mint.email
	}
	if mint.name != "" {
		claims["name"] = mint.name
	}

	if mint.signKey != nil {
		key, kid = mint.signKey, pick(mint.signKID, f.kid)
	}
	raw, err := signTestToken(claims, key, kid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeTestJSON(w, map[string]any{
		"access_token": "at-" + code,
		"token_type":   "Bearer",
		"id_token":     raw,
	})
}

func pick(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func signTestToken(claims map[string]any, key *rsa.PrivateKey, kid string) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		return "", fmt.Errorf("creating signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialising: %w", err)
	}
	return raw, nil
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestOIDC wires a provider, its store and a fresh transaction.
func newTestOIDC(t *testing.T) (*OIDCProvider, *fakeIDP, *SQLiteStore, AuthTransaction) {
	t.Helper()

	idp := newFakeIDP(t)
	provider, err := NewOIDCProvider(OIDCConfig{
		ID:          "test-oidc",
		Issuer:      idp.issuer,
		ClientID:    "client-1",
		RedirectURL: idp.issuer + "/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	store := openTestStore(t)
	tx, _, err := store.CreateAuthTransaction(NewAuthTransactionOptions{
		ProviderID:  provider.ID(),
		RedirectURI: provider.RedirectURL(),
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	return provider, idp, store, tx
}

func TestOIDCBeginAuthorizationURL(t *testing.T) {
	provider, idp, _, tx := newTestOIDC(t)

	req, err := provider.Begin(context.Background(), &tx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}
	if u.Scheme != "http" || u.Host != strings.TrimPrefix(idp.issuer, "http://") || u.Path != "/auth" {
		t.Fatalf("authorization URL = %q", req.URL)
	}

	q := u.Query()
	if q.Get("client_id") != "client-1" || q.Get("response_type") != "code" {
		t.Errorf("client_id/response_type = %q/%q", q.Get("client_id"), q.Get("response_type"))
	}
	if got := q.Get("redirect_uri"); got != idp.issuer+"/callback" {
		t.Errorf("redirect_uri = %q; it must come from configuration", got)
	}
	if q.Get("state") != tx.State || q.Get("nonce") != tx.Nonce {
		t.Error("state/nonce missing from the authorization URL")
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != PKCEChallenge(tx.PKCEVerifier) {
		t.Errorf("PKCE parameters = %q/%q", q.Get("code_challenge_method"), q.Get("code_challenge"))
	}
	for _, scope := range []string{"openid", "profile", "email"} {
		if !strings.Contains(q.Get("scope"), scope) {
			t.Errorf("scope %q missing from %q", scope, q.Get("scope"))
		}
	}
}

func TestOIDCHappyPath(t *testing.T) {
	provider, idp, _, tx := newTestOIDC(t)
	idp.setChallenge(tx.PKCEChallenge)
	idp.setMint(mintOptions{
		subject: "sub-42",
		nonce:   tx.Nonce,
		email:   "alice@example.com",
		name:    "Alice",
	})

	result, err := provider.Callback(context.Background(), &tx, &CallbackRequest{
		Code: "code-1", State: tx.State,
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.ProviderID != "test-oidc" || result.Subject != "sub-42" ||
		result.Email != "alice@example.com" || result.DisplayName != "Alice" {
		t.Fatalf("result = %+v", result)
	}
	if result.Claims["sub"] != "sub-42" {
		t.Errorf("claims = %+v", result.Claims)
	}
}

func TestOIDCJWKSRotation(t *testing.T) {
	provider, idp, _, tx := newTestOIDC(t)
	idp.setChallenge(tx.PKCEChallenge)

	// First login with key-1.
	idp.setMint(mintOptions{subject: "sub-1", nonce: tx.Nonce})
	if _, err := provider.Callback(context.Background(), &tx, &CallbackRequest{Code: "code-1", State: tx.State}); err != nil {
		t.Fatalf("Callback with key-1: %v", err)
	}

	// The provider rotates its signing key. The JWKS endpoint serves only the
	// new key, so the cached key cannot verify the next token.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	idp.rotateKeys(newKey, "key-2")
	idp.setMint(mintOptions{subject: "sub-2", nonce: tx.Nonce, signKey: newKey, signKID: "key-2"})

	result, err := provider.Callback(context.Background(), &tx, &CallbackRequest{Code: "code-2", State: tx.State})
	if err != nil {
		t.Fatalf("Callback after rotation: %v", err)
	}
	if result.Subject != "sub-2" {
		t.Errorf("subject after rotation = %q", result.Subject)
	}
}

func TestOIDCCallbackRejections(t *testing.T) {
	provider, idp, _, _ := newTestOIDC(t)

	// newTx returns a clean transaction with the fake IdP expecting its
	// challenge.
	newTx := func(t *testing.T) AuthTransaction {
		t.Helper()
		fresh, _, err := openTestStore(t).CreateAuthTransaction(NewAuthTransactionOptions{
			ProviderID: provider.ID(), RedirectURI: provider.RedirectURL(), TTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("CreateAuthTransaction: %v", err)
		}
		idp.setChallenge(fresh.PKCEChallenge)
		return fresh
	}

	call := func(t *testing.T, tx AuthTransaction, mint mintOptions, req *CallbackRequest) error {
		t.Helper()
		idp.setMint(mint)
		if req == nil {
			req = &CallbackRequest{State: tx.State}
		}
		if req.Code == "" {
			req.Code = idp.freshCode()
		}
		_, err := provider.Callback(context.Background(), &tx, req)
		return err
	}

	t.Run("wrong state", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{nonce: fresh.Nonce}, &CallbackRequest{Code: idp.freshCode(), State: "not-the-state"})
		if !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("error = %v, want ErrStateMismatch", err)
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		fresh := newTx(t)
		if err := call(t, fresh, mintOptions{nonce: "another-nonce"}, nil); !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("error = %v, want ErrNonceMismatch", err)
		}
	})

	t.Run("missing nonce", func(t *testing.T) {
		fresh := newTx(t)
		if err := call(t, fresh, mintOptions{}, nil); !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("error = %v, want ErrNonceMismatch", err)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{nonce: fresh.Nonce, issuer: "https://evil.example.com"}, nil)
		if err == nil || !strings.Contains(err.Error(), "different provider") {
			t.Fatalf("error = %v, want issuer rejection", err)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{nonce: fresh.Nonce, audience: "another-client"}, nil)
		if err == nil || !strings.Contains(err.Error(), "audience") {
			t.Fatalf("error = %v, want audience rejection", err)
		}
	})

	t.Run("expired id token", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{
			nonce:  fresh.Nonce,
			expiry: time.Now().Add(-time.Minute),
		}, nil)
		if err == nil {
			t.Fatal("expired id_token was accepted")
		}
	})

	t.Run("iat in the future", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{
			nonce:    fresh.Nonce,
			issuedAt: time.Now().Add(time.Hour),
		}, nil)
		if !errors.Is(err, ErrTokenFromFuture) {
			t.Fatalf("error = %v, want ErrTokenFromFuture", err)
		}
	})

	t.Run("iat too old", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{
			nonce:    fresh.Nonce,
			issuedAt: time.Now().Add(-2 * time.Hour),
		}, nil)
		if !errors.Is(err, ErrTokenTooOld) {
			t.Fatalf("error = %v, want ErrTokenTooOld", err)
		}
	})

	t.Run("signature from an unknown key", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{
			nonce:   fresh.Nonce,
			signKey: idp.otherKey,
			signKID: "unknown-key",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "verifying the id_token") {
			t.Fatalf("error = %v, want signature rejection", err)
		}
	})

	t.Run("no id_token", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{noToken: true}, nil)
		if err == nil || !strings.Contains(err.Error(), "no id_token") {
			t.Fatalf("error = %v, want missing id_token", err)
		}
	})

	t.Run("pkce verifier mismatch", func(t *testing.T) {
		fresh := newTx(t)
		idp.setChallenge("a-challenge-the-client-cannot-produce")
		err := call(t, fresh, mintOptions{nonce: fresh.Nonce}, nil)
		if err == nil || !strings.Contains(err.Error(), "exchanging the authorization code") {
			t.Fatalf("error = %v, want exchange failure", err)
		}
	})

	t.Run("code replay", func(t *testing.T) {
		fresh := newTx(t)
		idp.setMint(mintOptions{nonce: fresh.Nonce})
		req := &CallbackRequest{Code: "replayed-code", State: fresh.State}
		if _, err := provider.Callback(context.Background(), &fresh, req); err != nil {
			t.Fatalf("first exchange: %v", err)
		}
		if _, err := provider.Callback(context.Background(), &fresh, req); err == nil {
			t.Fatal("the provider's code was accepted twice")
		}
	})

	t.Run("provider error response", func(t *testing.T) {
		fresh := newTx(t)
		err := call(t, fresh, mintOptions{}, &CallbackRequest{Error: "access_denied", ErrorDescription: "user said no"})
		var pe *ProviderError
		if !errors.As(err, &pe) || pe.Code != "access_denied" {
			t.Fatalf("error = %v, want ProviderError{access_denied}", err)
		}
	})

	t.Run("missing code", func(t *testing.T) {
		fresh := newTx(t)
		idp.setMint(mintOptions{nonce: fresh.Nonce})
		if _, err := provider.Callback(context.Background(), &fresh, &CallbackRequest{State: fresh.State}); err == nil {
			t.Fatal("a callback without a code was accepted")
		}
	})
}

func TestNewOIDCProviderValidation(t *testing.T) {
	valid := OIDCConfig{
		Issuer:      "https://idp.example.com",
		ClientID:    "client",
		RedirectURL: "https://login.example.com/oidc/callback",
	}

	tests := []struct {
		name string
		cfg  OIDCConfig
	}{
		{"missing issuer", OIDCConfig{ClientID: "c", RedirectURL: valid.RedirectURL}},
		{"missing client ID", OIDCConfig{Issuer: valid.Issuer, RedirectURL: valid.RedirectURL}},
		{"missing redirect URL", OIDCConfig{Issuer: valid.Issuer, ClientID: "c"}},
		{"plaintext issuer", OIDCConfig{Issuer: "http://idp.example.com", ClientID: "c", RedirectURL: valid.RedirectURL}},
		{"plaintext redirect", OIDCConfig{Issuer: valid.Issuer, ClientID: "c", RedirectURL: "http://login.example.com/cb"}},
		{"non-http scheme", OIDCConfig{Issuer: "ftp://idp.example.com", ClientID: "c", RedirectURL: valid.RedirectURL}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewOIDCProvider(tc.cfg); err == nil {
				t.Fatal("configuration was accepted")
			}
		})
	}

	if _, err := NewOIDCProvider(valid); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	// Loopback http is the development exception.
	if _, err := NewOIDCProvider(OIDCConfig{
		Issuer:      "http://127.0.0.1:9999",
		ClientID:    "c",
		RedirectURL: "http://localhost:8080/oidc/callback",
	}); err != nil {
		t.Fatalf("loopback configuration rejected: %v", err)
	}
}

func TestOIDCDiscoveryIsLazyAndFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer server.Close()

	provider, err := NewOIDCProvider(OIDCConfig{
		Issuer:      server.URL,
		ClientID:    "client",
		RedirectURL: server.URL + "/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if _, err := provider.Begin(context.Background(), &AuthTransaction{State: "s", Nonce: "n", PKCEVerifier: "v"}); err == nil {
		t.Fatal("Begin succeeded against an issuer with no discovery document")
	}
}

func TestValidateSecureURL(t *testing.T) {
	ok := []string{
		"https://example.com/x",
		"http://localhost:8080/x",
		"http://127.0.0.1:8080/x",
		"http://[::1]:8080/x",
	}
	for _, raw := range ok {
		if err := ValidateSecureURL(raw); err != nil {
			t.Errorf("ValidateSecureURL(%q) = %v", raw, err)
		}
	}

	bad := []string{
		"http://example.com",
		"http://192.168.1.10:8080",
		"javascript:alert(1)",
		"data:text/html,x",
		"/relative/path",
		"example.com",
		"ftp://example.com",
	}
	for _, raw := range bad {
		if err := ValidateSecureURL(raw); err == nil {
			t.Errorf("ValidateSecureURL(%q) was accepted", raw)
		}
	}
}
