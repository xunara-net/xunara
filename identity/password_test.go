package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPasswordPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		login    string
		password string
		wantErr  error
	}{
		{name: "twelve characters", password: "twelve-chars", wantErr: nil},
		{name: "eleven characters", password: "eleven-char", wantErr: ErrPasswordTooShort},
		{name: "eleven chinese characters", password: strings.Repeat("密", 11), wantErr: ErrPasswordTooShort},
		{name: "twelve chinese characters", password: strings.Repeat("密", 12), wantErr: nil},
		{name: "too long", password: strings.Repeat("a", 73), wantErr: ErrPasswordTooLong},
		{name: "equal to the login name", login: "alice@example.com", password: "alice@example.com", wantErr: errors.New("identity: password must not be the login name")},
		{name: "equal to the login name, mixed case", login: "alice@example.com", password: "Alice@Example.Com", wantErr: errors.New("identity: password must not be the login name")},
		{name: "invalid UTF-8", password: "twelve-\xff\xfe-bytes", wantErr: errors.New("identity: password must be valid UTF-8")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(tc.login, tc.password)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("CheckPassword = %v, want nil", err)
			case tc.wantErr != nil && err == nil:
				t.Fatalf("CheckPassword = nil, want %v", tc.wantErr)
			case tc.wantErr != nil && err.Error() != tc.wantErr.Error():
				t.Fatalf("CheckPassword = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(string(hash), "$2") {
		t.Errorf("hash = %q, want a self-describing bcrypt hash", hash)
	}
	if strings.Contains(string(hash), password) {
		t.Error("the hash contains the password")
	}
	if !VerifyPassword(hash, password) {
		t.Error("VerifyPassword rejected the right password")
	}
	if VerifyPassword(hash, password+"x") {
		t.Error("VerifyPassword accepted a wrong password")
	}
	if VerifyPassword(nil, password) || VerifyPassword([]byte("not a hash"), password) {
		t.Error("VerifyPassword accepted a missing or corrupt hash")
	}

	// Two hashes of the same password differ: the salt is per hash.
	other, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if string(other) == string(hash) {
		t.Error("two hashes of the same password are identical")
	}
}

func TestVerifyPasswordMissingAlwaysFails(t *testing.T) {
	if VerifyPasswordMissing("correct horse battery staple") {
		t.Error("VerifyPasswordMissing accepted a password")
	}
	if VerifyPasswordMissing("") {
		t.Error("VerifyPasswordMissing accepted an empty password")
	}
}
