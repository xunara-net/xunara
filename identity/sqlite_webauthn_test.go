package identity

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// newTestPasskey returns a credential record as the library would report it.
func newTestPasskey(name string) webauthn.Credential {
	return webauthn.Credential{
		ID:        []byte("credential-" + name),
		PublicKey: []byte{0x01, 0x02, 0x03},
		Transport: []protocol.AuthenticatorTransport{protocol.Internal},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("aaguid"),
			SignCount: 7,
		},
	}
}

// TestPasskeyCRUD covers the credential lifecycle, including the uniqueness
// and ownership rules the login path relies on.
func TestPasskeyCRUD(t *testing.T) {
	s := openTestStore(t)

	alice := User{LoginName: "alice@example.com"}
	if err := s.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	bob := User{LoginName: "bob@example.com"}
	if err := s.CreateUser(&bob); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	p := Passkey{UserID: alice.ID, Name: "Laptop", CredentialID: []byte("credential-alice"), Credential: newTestPasskey("alice")}
	if err := s.CreatePasskey(&p); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	if p.ID == "" || p.CreatedAt.IsZero() {
		t.Fatalf("CreatePasskey did not assign bookkeeping: %+v", p)
	}

	loaded, ok := s.GetPasskeyByCredentialID([]byte("credential-alice"))
	if !ok {
		t.Fatal("GetPasskeyByCredentialID did not find the passkey")
	}
	if loaded.UserID != alice.ID || loaded.Name != "Laptop" || loaded.Credential.Authenticator.SignCount != 7 {
		t.Errorf("loaded passkey = %+v", loaded)
	}
	if !loaded.LastUsedAt.IsZero() {
		t.Errorf("a fresh passkey must report a zero last-used time, got %v", loaded.LastUsedAt)
	}

	// The same credential ID cannot be registered twice, by anyone.
	dup := Passkey{UserID: bob.ID, CredentialID: []byte("credential-alice"), Credential: newTestPasskey("dup")}
	if err := s.CreatePasskey(&dup); err == nil {
		t.Error("a duplicate credential ID was accepted")
	}

	list := s.ListPasskeys(alice.ID)
	if len(list) != 1 || list[0].ID != p.ID {
		t.Errorf("ListPasskeys = %+v", list)
	}
	if got := s.ListPasskeys(bob.ID); len(got) != 0 {
		t.Errorf("ListPasskeys for another user = %+v", got)
	}

	// The sign counter advances on every assertion and is persisted.
	updated := loaded.Credential
	updated.Authenticator.SignCount = 8
	usedAt := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.UpdatePasskey(p.ID, updated, usedAt); err != nil {
		t.Fatalf("UpdatePasskey: %v", err)
	}
	loaded, _ = s.GetPasskeyByCredentialID([]byte("credential-alice"))
	if loaded.Credential.Authenticator.SignCount != 8 {
		t.Errorf("sign count after update = %d, want 8", loaded.Credential.Authenticator.SignCount)
	}
	if !loaded.LastUsedAt.Equal(usedAt) {
		t.Errorf("last used = %v, want %v", loaded.LastUsedAt, usedAt)
	}

	if err := s.UpdatePasskey("pk_missing", updated, usedAt); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("UpdatePasskey for an unknown passkey = %v, want ErrPasskeyNotFound", err)
	}

	// Deletion is scoped to the owner: another user's ID must not work.
	if err := s.DeletePasskey(p.ID, bob.ID); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("DeletePasskey by another user = %v, want ErrPasskeyNotFound", err)
	}
	if _, ok := s.GetPasskeyByCredentialID([]byte("credential-alice")); !ok {
		t.Error("a failed delete removed the passkey")
	}
	if err := s.DeletePasskey(p.ID, alice.ID); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	if _, ok := s.GetPasskeyByCredentialID([]byte("credential-alice")); ok {
		t.Error("DeletePasskey left the passkey behind")
	}
	if err := s.DeletePasskey(p.ID, alice.ID); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("second DeletePasskey = %v, want ErrPasskeyNotFound", err)
	}
}

// TestPasskeyDeletedWithUser checks that deleting a user removes its passkeys
// and ceremonies; a stale credential must never sign anyone in.
func TestPasskeyDeletedWithUser(t *testing.T) {
	s := openTestStore(t)

	alice := User{LoginName: "alice@example.com"}
	if err := s.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	p := Passkey{UserID: alice.ID, CredentialID: []byte("credential-alice"), Credential: newTestPasskey("alice")}
	if err := s.CreatePasskey(&p); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	ceremony, _, err := s.CreatePasskeyCeremony(NewPasskeyCeremonyOptions{
		Kind:    PasskeyCeremonyRegister,
		UserID:  alice.ID,
		Session: []byte(`{"challenge":"x"}`),
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}

	if err := s.DeleteUser(alice.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok := s.GetPasskeyByCredentialID([]byte("credential-alice")); ok {
		t.Error("deleting the user left the passkey behind")
	}
	if _, ok := s.GetPasskeyCeremony(ceremony.ID); ok {
		t.Error("deleting the user left the ceremony behind")
	}
}

// TestPasskeyCeremonyLifecycle covers single use, expiry and the browser
// binding secret.
func TestPasskeyCeremonyLifecycle(t *testing.T) {
	s := openTestStore(t)

	alice := User{LoginName: "alice@example.com"}
	if err := s.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	session := []byte(`{"challenge":"abc"}`)
	ceremony, browserSecret, err := s.CreatePasskeyCeremony(NewPasskeyCeremonyOptions{
		Kind:    PasskeyCeremonyRegister,
		UserID:  alice.ID,
		Session: session,
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}
	if browserSecret == "" || ceremony.BrowserSessionHash == "" {
		t.Fatalf("ceremony has no browser binding: %+v", ceremony)
	}
	if ceremony.BrowserSessionHash == browserSecret {
		t.Error("the browser secret is stored verbatim")
	}
	stored, ok := s.GetPasskeyCeremony(ceremony.ID)
	if !ok {
		t.Fatal("GetPasskeyCeremony did not find the ceremony")
	}
	if !bytes.Equal(stored.Session, session) || stored.Kind != PasskeyCeremonyRegister || stored.UserID != alice.ID {
		t.Errorf("stored ceremony = %+v", stored)
	}
	if stored.ExpiresAt.Before(time.Now()) {
		t.Errorf("ceremony expires in the past: %v", stored.ExpiresAt)
	}

	// First finish wins; a replayed response is refused.
	if _, err := s.ConsumePasskeyCeremony(ceremony.ID); err != nil {
		t.Fatalf("ConsumePasskeyCeremony: %v", err)
	}
	if _, err := s.ConsumePasskeyCeremony(ceremony.ID); !errors.Is(err, ErrPasskeyCeremonyConsumed) {
		t.Errorf("replayed ceremony = %v, want ErrPasskeyCeremonyConsumed", err)
	}

	if _, err := s.ConsumePasskeyCeremony("wc_missing"); !errors.Is(err, ErrPasskeyCeremonyNotFound) {
		t.Errorf("unknown ceremony = %v, want ErrPasskeyCeremonyNotFound", err)
	}

	// An expired ceremony can never be finished.
	expired, _, err := s.CreatePasskeyCeremony(NewPasskeyCeremonyOptions{
		Kind:      PasskeyCeremonyLogin,
		Session:   session,
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}
	if _, err := s.ConsumePasskeyCeremony(expired.ID); !errors.Is(err, ErrPasskeyCeremonyExpired) {
		t.Errorf("expired ceremony = %v, want ErrPasskeyCeremonyExpired", err)
	}

	// The reaper removes expired ceremonies but keeps live ones.
	live, _, err := s.CreatePasskeyCeremony(NewPasskeyCeremonyOptions{
		Kind:    PasskeyCeremonyLogin,
		Session: session,
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}
	deleted, err := s.DeleteExpiredPasskeyCeremonies(time.Now().UTC())
	if err != nil {
		t.Fatalf("DeleteExpiredPasskeyCeremonies: %v", err)
	}
	if deleted != 1 {
		t.Errorf("reaped %d ceremonies, want 1 (only the expired one)", deleted)
	}
	if _, ok := s.GetPasskeyCeremony(live.ID); !ok {
		t.Error("the reaper removed a live ceremony")
	}
}

// TestPasskeyCeremonyValidation checks the fail-closed inputs.
func TestPasskeyCeremonyValidation(t *testing.T) {
	s := openTestStore(t)

	alice := User{LoginName: "alice@example.com"}
	if err := s.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cases := []struct {
		name string
		opts NewPasskeyCeremonyOptions
	}{
		{"unknown kind", NewPasskeyCeremonyOptions{Kind: "otp", Session: []byte("{}")}},
		{"registration without a user", NewPasskeyCeremonyOptions{Kind: PasskeyCeremonyRegister, Session: []byte("{}")}},
		{"usernameless login with a user", NewPasskeyCeremonyOptions{Kind: PasskeyCeremonyLogin, UserID: alice.ID, Session: []byte("{}")}},
		{"missing session", NewPasskeyCeremonyOptions{Kind: PasskeyCeremonyLogin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := s.CreatePasskeyCeremony(tc.opts); err == nil {
				t.Fatal("CreatePasskeyCeremony accepted an invalid ceremony")
			}
		})
	}
}
