package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Sealed secrets at rest.
//
// Several platform features keep operator secrets in the state directory:
// webhook signing secrets and the tailnet-lock support disablement secret.
// They are sealed with AES-256-GCM under a key file that lives next to the
// rest of the server state, 0600, and never leaves the process, so a database
// dump or a copied state file alone never yields a usable secret (AGENTS.md
// section 8).

// sealedSecretPrefix marks the sealed format so a future key rotation can
// recognise old blobs.
const sealedSecretPrefix = "v1:"

// loadOrCreateSealingKey returns the AES-256 key stored at path, generating and
// persisting it on first use.
func loadOrCreateSealingKey(path string) ([32]byte, error) {
	var key [32]byte

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != len(key) {
			return key, fmt.Errorf("control: %s must hold exactly %d bytes", path, len(key))
		}
		copy(key[:], raw)
		if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().Perm()&0o077 != 0 {
			return key, fmt.Errorf("control: %s is readable beyond its owner (%s)", path, fi.Mode().Perm())
		}
		return key, nil

	case errors.Is(err, os.ErrNotExist):
		if _, err := rand.Read(key[:]); err != nil {
			return key, fmt.Errorf("control: generating %s: %w", filepath.Base(path), err)
		}
		// O_EXCL: if two processes race to create the key, the loser reads the
		// winner's key instead of replacing it (which would orphan every
		// sealed secret).
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return loadOrCreateSealingKey(path)
			}
			return key, fmt.Errorf("control: creating %s: %w", path, err)
		}
		if _, err := f.Write(key[:]); err != nil {
			f.Close()
			return key, fmt.Errorf("control: writing %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return key, fmt.Errorf("control: writing %s: %w", path, err)
		}
		return key, nil

	default:
		return key, fmt.Errorf("control: reading %s: %w", path, err)
	}
}

// sealSecret encrypts a secret for storage. The plaintext is a UTF-8 string;
// binary secrets are stored base64-encoded by their callers.
func sealSecret(key [32]byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("control: secret is empty")
	}
	aead, err := newSecretAEAD(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("control: sealing secret: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return sealedSecretPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// openSecret decrypts a stored secret.
func openSecret(key [32]byte, sealed string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, sealedSecretPrefix)
	if !ok {
		return "", errors.New("control: unsupported sealed secret format")
	}
	blob, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("control: decoding sealed secret: %w", err)
	}

	aead, err := newSecretAEAD(key)
	if err != nil {
		return "", err
	}
	if len(blob) < aead.NonceSize() {
		return "", errors.New("control: sealed secret is truncated")
	}
	plaintext, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
	if err != nil {
		// Never include the underlying error text: it can only say "wrong
		// key", which is exactly what an attacker wants to confirm.
		return "", errors.New("control: sealed secret cannot be decrypted with this server's key")
	}
	return string(plaintext), nil
}

// newSecretAEAD builds the AES-256-GCM primitive used for sealed secrets.
func newSecretAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("control: secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("control: secret cipher: %w", err)
	}
	return aead, nil
}
