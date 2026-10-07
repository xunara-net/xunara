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

// Sealing for operator-managed webhook signing secrets.
//
// The trust plane stores a webhook endpoint's secret as an opaque string, so a
// database dump alone never yields a usable HMAC key (AGENTS.md section 8).
// The sealing key lives next to the server's other state, 0600, and never
// leaves the process.
//
// Deployments that configure webhooks through flags/environment keep their
// secrets in the environment: those are never written to the database at all.

// webhookSecretKeyFile is the sealing key inside the state directory.
const webhookSecretKeyFile = "webhook_secret.key"

// webhookSecretPrefix marks the sealed format so a future key rotation can
// recognise old blobs.
const webhookSecretPrefix = "v1:"

// loadOrCreateWebhookSecretKey returns the AES-256 key used to seal webhook
// secrets, generating and persisting it on first use.
func loadOrCreateWebhookSecretKey(stateDir string) ([32]byte, error) {
	var key [32]byte
	path := filepath.Join(stateDir, webhookSecretKeyFile)

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
			return key, fmt.Errorf("control: generating webhook secret key: %w", err)
		}
		// O_EXCL: if two processes race to create the key, the loser reads the
		// winner's key instead of replacing it (which would orphan every
		// sealed secret).
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return loadOrCreateWebhookSecretKey(stateDir)
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

// sealWebhookSecret encrypts a signing secret for storage.
func sealWebhookSecret(key [32]byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("control: webhook secret is empty")
	}
	aead, err := newSecretAEAD(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("control: sealing webhook secret: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return webhookSecretPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// openWebhookSecret decrypts a stored signing secret.
func openWebhookSecret(key [32]byte, sealed string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, webhookSecretPrefix)
	if !ok {
		return "", errors.New("control: unsupported webhook secret format")
	}
	blob, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("control: decoding webhook secret: %w", err)
	}

	aead, err := newSecretAEAD(key)
	if err != nil {
		return "", err
	}
	if len(blob) < aead.NonceSize() {
		return "", errors.New("control: webhook secret is truncated")
	}
	plaintext, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
	if err != nil {
		// Never include the underlying error text: it can only say "wrong
		// key", which is exactly what an attacker wants to confirm.
		return "", errors.New("control: webhook secret cannot be decrypted with this server's key")
	}
	return string(plaintext), nil
}

// newSecretAEAD builds the AES-256-GCM primitive used for sealed secrets.
func newSecretAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("control: webhook secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("control: webhook secret cipher: %w", err)
	}
	return aead, nil
}
