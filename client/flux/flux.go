// Package flux implements the end-to-end half of Xunara Flux, the file
// transfer between xunara-agent nodes (PROJECT_SPEC section 25).
//
// The control plane relays ciphertext it cannot read, so everything that
// protects file content lives here:
//
//   - the recipient keeps one local seed and derives a fresh X25519 key pair
//     per transfer from it, so accepting one transfer never exposes another;
//   - the sender generates a one-time X25519 key pair per upload and seals the
//     content with AES-256-GCM under a key derived from the ECDH shared
//     secret;
//   - nothing here trusts the control plane: the recipient verifies the
//     plaintext digest the sender declared before the transfer completes
//     (that check lives in the caller, which knows the expected digest).
//
// The seed is the root of every transfer this agent can decrypt: losing it
// makes in-flight transfers undecryptable, and leaking it exposes every
// transfer addressed to this agent, so it is stored 0600 and never sent
// anywhere.
package flux

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Sizes and file names of the on-disk and on-the-wire formats.
const (
	// SeedFileName is the Flux seed inside the agent state directory.
	SeedFileName = "flux.seed"
	// SeedSize is the seed length in bytes; it is also the derived key
	// length, because the seed is used as HKDF input keying material.
	SeedSize = 32
	// PublicKeySize is the size of an X25519 public key.
	PublicKeySize = 32
	// NonceSize is the AES-GCM nonce size.
	NonceSize = 12
	// TagSize is the AES-GCM authentication tag size.
	TagSize = 16
	// Overhead is how much larger a sealed file is than its plaintext:
	// ephemeral public key + nonce + tag. It matches the control plane's
	// limit (section 25.2).
	Overhead = PublicKeySize + NonceSize + TagSize
)

// infoPrefixes are the HKDF domain-separation strings (section 25.4). They
// are versioned: a future format change must not silently reuse this schedule.
const (
	recipientInfoPrefix = "xunara-flux-recipient|"
	contentInfoPrefix   = "xunara-flux-v1|"
)

// LoadOrCreateSeed returns the Flux seed in stateDir, generating it on first
// use. A pre-existing seed with permissions wider than 0600 is refused: a
// readable seed lets any local user decrypt every transfer addressed to this
// agent, so failing closed is safer than quietly accepting it.
func LoadOrCreateSeed(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, SeedFileName)
	seed, err := readSeed(path)
	if err == nil {
		return seed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("flux: creating state directory: %w", err)
	}
	fresh := make([]byte, SeedSize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("flux: generating seed: %w", err)
	}
	// O_EXCL keeps concurrent first uses on one seed: a process that loses
	// the race reads the winner's file instead of replacing it, so an
	// accepted transfer is never tied to a seed that no longer exists.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return readSeed(path)
		}
		return nil, fmt.Errorf("flux: creating seed: %w", err)
	}
	if _, err := f.Write(fresh); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("flux: writing seed: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("flux: closing seed: %w", err)
	}
	return fresh, nil
}

// readSeed loads and validates an existing seed file.
func readSeed(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("flux: %s has mode %04o; a seed readable by other users cannot be trusted, run chmod 600", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != SeedSize {
		return nil, fmt.Errorf("flux: %s is %d bytes, want %d", path, len(raw), SeedSize)
	}
	return raw, nil
}

// RecipientKey derives the recipient key pair for one transfer from the seed
// (section 25.4). The transfer ID is part of the HKDF info, so two transfers
// never share a key.
func RecipientKey(seed []byte, transferID string) (*ecdh.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("flux: seed is %d bytes, want %d", len(seed), SeedSize)
	}
	if transferID == "" {
		return nil, errors.New("flux: a transfer id is required to derive a recipient key")
	}
	raw, err := hkdf.Key(sha256.New, seed, nil, recipientInfoPrefix+transferID, SeedSize)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving recipient key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving recipient key: %w", err)
	}
	return priv, nil
}

// RecipientPublicKey returns the public half the recipient sends in Accept.
// The public key is not a secret; the private half never leaves this package.
func RecipientPublicKey(seed []byte, transferID string) ([]byte, error) {
	priv, err := RecipientKey(seed, transferID)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// Seal encrypts plaintext for the recipient's per-transfer public key. The
// result is epk(32) || nonce(12) || AES-256-GCM ciphertext, which is what the
// sender uploads; the control plane stores it verbatim and can read nothing.
func Seal(recipientPublicKey []byte, transferID string, plaintext []byte) ([]byte, error) {
	if transferID == "" {
		return nil, errors.New("flux: a transfer id is required to seal content")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("flux: invalid recipient public key: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("flux: generating ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving shared secret: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, contentInfoPrefix+transferID, SeedSize)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving content key: %w", err)
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("flux: generating nonce: %w", err)
	}

	sealed := make([]byte, 0, Overhead+len(plaintext))
	sealed = append(sealed, ephemeral.PublicKey().Bytes()...)
	sealed = append(sealed, nonce...)
	return aead.Seal(sealed, nonce, plaintext, nil), nil
}

// Open decrypts content sealed for this seed. It returns an error when the
// ciphertext is not for this seed, was modified, or is too short; the caller
// still has to verify the plaintext digest against the declared one.
func Open(seed []byte, transferID string, sealed []byte) ([]byte, error) {
	if len(sealed) < Overhead {
		return nil, fmt.Errorf("flux: ciphertext is %d bytes, want at least %d", len(sealed), Overhead)
	}
	priv, err := RecipientKey(seed, transferID)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(sealed[:PublicKeySize])
	if err != nil {
		return nil, fmt.Errorf("flux: invalid ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving shared secret: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, contentInfoPrefix+transferID, SeedSize)
	if err != nil {
		return nil, fmt.Errorf("flux: deriving content key: %w", err)
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := sealed[PublicKeySize : PublicKeySize+NonceSize]
	plaintext, err := aead.Open(nil, nonce, sealed[PublicKeySize+NonceSize:], nil)
	if err != nil {
		return nil, errors.New("flux: decryption failed: the content is not for this agent or was modified in transit")
	}
	return plaintext, nil
}

// newGCM builds AES-256-GCM from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("flux: creating cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("flux: creating AEAD: %w", err)
	}
	return aead, nil
}
