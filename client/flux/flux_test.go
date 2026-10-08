package flux

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateSeedPersists(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateSeed(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateSeed: %v", err)
	}
	if len(first) != SeedSize {
		t.Fatalf("seed is %d bytes, want %d", len(first), SeedSize)
	}

	path := filepath.Join(dir, SeedFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat seed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("seed mode is %04o, want 0600", perm)
	}

	second, err := LoadOrCreateSeed(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateSeed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("the seed changed between loads")
	}
}

func TestLoadOrCreateSeedRejectsWeakPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateSeed(dir); err != nil {
		t.Fatalf("LoadOrCreateSeed: %v", err)
	}
	path := filepath.Join(dir, SeedFileName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := LoadOrCreateSeed(dir); err == nil {
		t.Fatal("LoadOrCreateSeed accepted a group/world-readable seed")
	}
}

func TestLoadOrCreateSeedRejectsBadLength(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SeedFileName), make([]byte, 16), 0o600); err != nil {
		t.Fatalf("writing seed: %v", err)
	}
	if _, err := LoadOrCreateSeed(dir); err == nil {
		t.Fatal("LoadOrCreateSeed accepted a 16-byte seed")
	}
}

func TestSeedIsNotOverwrittenByALoser(t *testing.T) {
	dir := t.TempDir()
	seed, err := LoadOrCreateSeed(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateSeed: %v", err)
	}

	// A concurrent first use must read the winner's file, not replace it.
	path := filepath.Join(dir, SeedFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	again, err := LoadOrCreateSeed(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateSeed again: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed again: %v", err)
	}
	if !bytes.Equal(before, after) || !bytes.Equal(again, seed) {
		t.Error("the seed file changed on a repeated load")
	}
}

func TestRecipientKeyIsDeterministicAndTransferScoped(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}

	first, err := RecipientPublicKey(seed, "fx_aaaa")
	if err != nil {
		t.Fatalf("RecipientPublicKey: %v", err)
	}
	again, err := RecipientPublicKey(seed, "fx_aaaa")
	if err != nil {
		t.Fatalf("RecipientPublicKey again: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Error("the same seed and transfer ID produced different keys")
	}
	if len(first) != PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(first), PublicKeySize)
	}

	other, err := RecipientPublicKey(seed, "fx_bbbb")
	if err != nil {
		t.Fatalf("RecipientPublicKey other: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Error("two transfers share a recipient key")
	}

	otherSeed := make([]byte, SeedSize)
	if _, err := rand.Read(otherSeed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	foreign, err := RecipientPublicKey(otherSeed, "fx_aaaa")
	if err != nil {
		t.Fatalf("RecipientPublicKey foreign: %v", err)
	}
	if bytes.Equal(first, foreign) {
		t.Error("two seeds derived the same recipient key")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	public, err := RecipientPublicKey(seed, "fx_0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatalf("RecipientPublicKey: %v", err)
	}

	for _, size := range []int{0, 1, 15, 1 << 10, 1 << 16} {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		sealed, err := Seal(public, "fx_0102030405060708090a0b0c0d0e0f10", plaintext)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", size, err)
		}
		if len(sealed) != len(plaintext)+Overhead {
			t.Fatalf("sealed %d bytes is %d long, want %d", size, len(sealed), len(plaintext)+Overhead)
		}
		opened, err := Open(seed, "fx_0102030405060708090a0b0c0d0e0f10", sealed)
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", size, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("round trip of %d bytes changed the plaintext", size)
		}
	}
}

func TestSealUsesFreshEphemeralKeys(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	public, err := RecipientPublicKey(seed, "fx_0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatalf("RecipientPublicKey: %v", err)
	}

	plaintext := []byte("same plaintext")
	first, err := Seal(public, "fx_0102030405060708090a0b0c0d0e0f10", plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := Seal(public, "fx_0102030405060708090a0b0c0d0e0f10", plaintext)
	if err != nil {
		t.Fatalf("Seal again: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("two seals of the same plaintext are byte-identical")
	}
}

func TestOpenRejectsWrongRecipient(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	const id = "fx_0102030405060708090a0b0c0d0e0f10"
	public, err := RecipientPublicKey(seed, id)
	if err != nil {
		t.Fatalf("RecipientPublicKey: %v", err)
	}
	sealed, err := Seal(public, id, []byte("for one agent only"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	other := make([]byte, SeedSize)
	if _, err := rand.Read(other); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := Open(other, id, sealed); err == nil {
		t.Error("another seed decrypted the content")
	}
	if _, err := Open(seed, "fx_ffffffffffffffffffffffffffffffff", sealed); err == nil {
		t.Error("another transfer ID decrypted the content")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	const id = "fx_0102030405060708090a0b0c0d0e0f10"
	public, err := RecipientPublicKey(seed, id)
	if err != nil {
		t.Fatalf("RecipientPublicKey: %v", err)
	}
	sealed, err := Seal(public, id, []byte("integrity matters"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, at := range []int{0, PublicKeySize, PublicKeySize + NonceSize, len(sealed) - 1} {
		tampered := bytes.Clone(sealed)
		tampered[at] ^= 0x01
		if _, err := Open(seed, id, tampered); err == nil {
			t.Errorf("Open accepted tampering at byte %d", at)
		}
	}
}

func TestOpenRejectsShortCiphertext(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := Open(seed, "fx_0102030405060708090a0b0c0d0e0f10", make([]byte, Overhead-1)); err == nil {
		t.Fatal("Open accepted a short ciphertext")
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	if _, err := Seal(make([]byte, 16), "fx_0102030405060708090a0b0c0d0e0f10", []byte("x")); err == nil {
		t.Fatal("Seal accepted a 16-byte public key")
	}
	if _, err := Seal(make([]byte, PublicKeySize), "fx_0102030405060708090a0b0c0d0e0f10", []byte("x")); err == nil {
		t.Fatal("Seal accepted the all-zero public key")
	}
}

func TestTransferIDRequired(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := RecipientKey(seed, ""); err == nil {
		t.Error("RecipientKey accepted an empty transfer ID")
	}
	if _, err := Seal(make([]byte, PublicKeySize), "", []byte("x")); err == nil {
		t.Error("Seal accepted an empty transfer ID")
	}
}

func TestSeedErrorsAreNotExist(t *testing.T) {
	// Losing the "not exist" classification would make LoadOrCreateSeed
	// report an I/O failure on a first run instead of generating a seed.
	if _, err := LoadOrCreateSeed(t.TempDir()); err != nil {
		t.Fatalf("LoadOrCreateSeed on an empty directory: %v", err)
	}
	if _, err := readSeed(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("readSeed of a missing file = %v, want os.ErrNotExist", err)
	}
}
