package control

import (
	"path/filepath"
)

// Sealing for operator-managed webhook signing secrets.
//
// The trust plane stores a webhook endpoint's secret as an opaque string, so a
// database dump alone never yields a usable HMAC key (AGENTS.md section 8).
// The sealing key lives next to the server's other state, 0600, and never
// leaves the process; the primitive itself is shared with the other sealed
// secrets in [sealSecret].
//
// Deployments that configure webhooks through flags/environment keep their
// secrets in the environment: those are never written to the database at all.

// webhookSecretKeyFile is the sealing key inside the state directory.
const webhookSecretKeyFile = "webhook_secret.key"

// loadOrCreateWebhookSecretKey returns the AES-256 key used to seal webhook
// secrets, generating and persisting it on first use.
func loadOrCreateWebhookSecretKey(stateDir string) ([32]byte, error) {
	return loadOrCreateSealingKey(filepath.Join(stateDir, webhookSecretKeyFile))
}

// sealWebhookSecret encrypts a signing secret for storage.
func sealWebhookSecret(key [32]byte, plaintext string) (string, error) {
	return sealSecret(key, plaintext)
}

// openWebhookSecret decrypts a stored signing secret.
func openWebhookSecret(key [32]byte, sealed string) (string, error) {
	return openSecret(key, sealed)
}
