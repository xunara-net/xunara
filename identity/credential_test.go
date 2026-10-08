package identity

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestLocalCredentialStore(t *testing.T) {
	s := openTestStore(t)

	if got := s.CountLocalCredentials(); got != 0 {
		t.Fatalf("CountLocalCredentials on a fresh store = %d, want 0", got)
	}
	if _, ok := s.GetLocalCredential(tailcfg.UserID(1)); ok {
		t.Fatal("GetLocalCredential returned a credential for an unknown user")
	}

	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s.SetLocalCredential(&LocalCredential{UserID: 1, PasswordHash: hash}); err != nil {
		t.Fatalf("SetLocalCredential: %v", err)
	}
	if got := s.CountLocalCredentials(); got != 1 {
		t.Errorf("CountLocalCredentials = %d, want 1", got)
	}

	got, ok := s.GetLocalCredential(1)
	if !ok || !VerifyPassword(got.PasswordHash, "correct horse battery staple") {
		t.Fatalf("GetLocalCredential = %+v, %v", got, ok)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("the credential has no timestamps")
	}

	// Replacing a password keeps the row and updates it in place.
	replacement, err := HashPassword("another long password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s.SetLocalCredential(&LocalCredential{UserID: 1, PasswordHash: replacement}); err != nil {
		t.Fatalf("SetLocalCredential (replace): %v", err)
	}
	if got := s.CountLocalCredentials(); got != 1 {
		t.Errorf("CountLocalCredentials after replacement = %d, want 1", got)
	}
	if updated, _ := s.GetLocalCredential(1); !VerifyPassword(updated.PasswordHash, "another long password") {
		t.Error("the replacement password does not verify")
	}

	// Credentials are independent per user.
	if err := s.SetLocalCredential(&LocalCredential{UserID: 2, PasswordHash: hash}); err != nil {
		t.Fatalf("SetLocalCredential (second user): %v", err)
	}
	if got := s.CountLocalCredentials(); got != 2 {
		t.Errorf("CountLocalCredentials = %d, want 2", got)
	}
	if err := s.DeleteLocalCredential(1); err != nil {
		t.Fatalf("DeleteLocalCredential: %v", err)
	}
	if _, ok := s.GetLocalCredential(1); ok {
		t.Error("the deleted credential is still present")
	}
	if got := s.CountLocalCredentials(); got != 1 {
		t.Errorf("CountLocalCredentials = %d, want 1", got)
	}
	if err := s.DeleteLocalCredential(1); err != nil {
		t.Errorf("deleting a missing credential = %v, want nil", err)
	}
}
