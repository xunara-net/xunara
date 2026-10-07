package state

import (
	"errors"
	"time"
)

// ErrPreAuthKeyExists is returned when a pre-auth key secret is already stored.
var ErrPreAuthKeyExists = errors.New("pre-auth key already exists")

// PreAuthKeyStore is the pre-authentication key half of the persistence
// boundary, split out so the node store can be consumed on its own.
type PreAuthKeyStore interface {
	// CreatePreAuthKey stores a new key, assigning its ID and creation time.
	CreatePreAuthKey(k *PreAuthKey) error
	// GetPreAuthKey returns the key with the given secret.
	GetPreAuthKey(secret string) (PreAuthKey, bool)
	// ListPreAuthKeys returns every key, oldest first.
	ListPreAuthKeys() []PreAuthKey
	// MarkPreAuthKeyUsed records that a key authorized a node.
	MarkPreAuthKeyUsed(secret string, at time.Time) error
	// DeletePreAuthKey removes a key. It is a no-op if the key is unknown.
	DeletePreAuthKey(secret string) error
}
