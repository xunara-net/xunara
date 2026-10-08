package identity

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Password credentials for the built-in local sign-in.
//
// The hash is self-describing (bcrypt carries its own algorithm, cost and
// salt), so a later move to Argon2id can rehash on the next successful login
// instead of a migration. Credentials live in the store, never in a
// server-local map: every instance of the control plane verifies the same
// password, and a restart does not lose them (AGENTS.md section 9).

// MinPasswordLength is the shortest local password the setup, registration
// and reset forms accept. Length is the only rule: character-class rules push
// people towards predictable substitutions without adding entropy.
const MinPasswordLength = 12

// maxPasswordBytes is bcrypt's input limit: a longer password is silently
// truncated by the algorithm, so it is rejected instead of accepted with
// fewer effective characters than the operator believes they typed.
const maxPasswordBytes = 72

// ErrPasswordTooShort, ErrPasswordTooLong and ErrPasswordUnchanged are
// returned by [CheckPassword] so every surface rejects the same inputs.
var (
	ErrPasswordTooShort = fmt.Errorf("identity: password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("identity: password must be at most %d bytes", maxPasswordBytes)
)

// dummyHash is a valid bcrypt hash of a password nobody knows and nobody may
// use. Verifying against it when the account does not exist keeps the cost of
// a failed login the same whether or not the login name is taken, so the
// sign-in endpoint does not confirm which names exist.
const dummyHash = "$2a$10$ry2kzOSJ9W7/fsHgKKkeYeFqCRnNobuhEPCQjv0YfUeJKxEoF7l8a"

// CheckPassword validates a new password against the policy. login is the
// account the password belongs to, so a password equal to the login name is
// rejected.
func CheckPassword(login, password string) error {
	if !utf8.ValidString(password) {
		return errors.New("identity: password must be valid UTF-8")
	}
	// Count characters, not bytes: a passphrase of Chinese characters is
	// strong at a third of the length in bytes.
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > maxPasswordBytes {
		return ErrPasswordTooLong
	}
	if login != "" && strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(login)) {
		return errors.New("identity: password must not be the login name")
	}
	return nil
}

// HashPassword returns the stored form of a password.
func HashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("identity: hashing password: %w", err)
	}
	return hash, nil
}

// VerifyPassword reports whether password matches hash. It is safe against a
// nil or corrupt hash: the comparison simply fails.
func VerifyPassword(hash []byte, password string) bool {
	if len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// VerifyPasswordMissing burns the same work as [VerifyPassword] for a login
// name that has no credential, and always fails.
func VerifyPasswordMissing(password string) bool {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
	return false
}
