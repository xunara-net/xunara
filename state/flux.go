package state

// This file holds the control plane's bookkeeping for Xunara Flux file
// transfers (PROJECT_SPEC section 25). The control plane stores metadata and
// opaque ciphertext; it never sees plaintext, and a transfer only moves
// forward when both sides act (the sender offers, the recipient accepts).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// FluxTransferState is where a transfer is in its lifecycle.
type FluxTransferState string

const (
	// FluxPending: the sender offered, the recipient has not answered.
	FluxPending FluxTransferState = "pending"
	// FluxAccepted: the recipient accepted and published its per-transfer
	// X25519 public key; the sender may upload ciphertext.
	FluxAccepted FluxTransferState = "accepted"
	// FluxUploaded: ciphertext is stored; the recipient may download it.
	FluxUploaded FluxTransferState = "uploaded"
	// FluxCompleted: the recipient decrypted and verified the content.
	FluxCompleted FluxTransferState = "completed"
	// FluxDenied: the recipient refused the offer.
	FluxDenied FluxTransferState = "denied"
	// FluxFailed: the recipient could not decrypt or verify the content.
	FluxFailed FluxTransferState = "failed"
	// FluxCancelled: the sender withdrew the offer.
	FluxCancelled FluxTransferState = "cancelled"
	// FluxExpired: the transfer passed its TTL.
	FluxExpired FluxTransferState = "expired"
)

// Active reports whether the transfer still holds resources (or waits for an
// action). Terminal transfers are kept briefly so both sides can read the
// outcome, then pruned.
func (s FluxTransferState) Active() bool {
	switch s {
	case FluxPending, FluxAccepted, FluxUploaded:
		return true
	default:
		return false
	}
}

// Valid reports whether the state is one this build knows.
func (s FluxTransferState) Valid() bool {
	switch s {
	case FluxPending, FluxAccepted, FluxUploaded, FluxCompleted,
		FluxDenied, FluxFailed, FluxCancelled, FluxExpired:
		return true
	default:
		return false
	}
}

// FluxReasonLimit bounds the static explanation a peer attaches to a denial or
// failure. It is displayed to the other side, never trusted as data.
const FluxReasonLimit = 200

// FluxTransfer is one transfer's metadata. Content is opaque ciphertext the
// control plane keeps next to its database, keyed by ID; it is never part of
// this record and never readable here.
type FluxTransfer struct {
	ID            string
	SenderNode    NodeID
	RecipientNode NodeID
	// Name is the file name the sender proposed (a basename, no path).
	Name string
	// Size is the plaintext size in bytes; the stored ciphertext is a little
	// larger (section 25.2).
	Size int64
	// SHA256 is the plaintext digest (lowercase hex), verified by the
	// recipient after decryption.
	SHA256 string
	State  FluxTransferState
	// RecipientKey is the X25519 public key the recipient published in
	// accept; empty until then.
	RecipientKey []byte
	// Reason explains a denial/failure in static text; empty otherwise.
	Reason    string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

// fluxRole identifies which side of a transfer a transition belongs to.
type fluxRole int

const (
	fluxSenderRole fluxRole = iota
	fluxRecipientRole
)

// FluxQuotas bounds how much one organization may store. Zero fields mean "no
// limit" (the control plane always passes explicit defaults).
type FluxQuotas struct {
	// MaxActivePerNode bounds pending+accepted+uploaded transfers a node is
	// part of, in either role.
	MaxActivePerNode int
	// MaxActiveTotal bounds active transfers in the organization.
	MaxActiveTotal int
	// MaxStoredBytes bounds the total plaintext size of uploaded content.
	MaxStoredBytes int64
}

var (
	// ErrFluxTransferNotFound is returned when a transfer does not exist or
	// the caller is not one of its two nodes. The two cases are deliberately
	// indistinguishable: IDs must not probe other nodes' transfers.
	ErrFluxTransferNotFound = errors.New("state: flux transfer not found")
	// ErrFluxTransferState is returned when a transfer exists but is not in a
	// state (or role) that allows the requested transition.
	ErrFluxTransferState = errors.New("state: flux transfer is not in a state that allows this")
	// ErrFluxQuota is returned when a new transfer would exceed [FluxQuotas].
	ErrFluxQuota = errors.New("state: flux quota exceeded")
)

// NewFluxTransferID returns a fresh random transfer ID.
func NewFluxTransferID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("state: generating flux transfer ID: %w", err)
	}
	return "fx_" + hex.EncodeToString(raw[:]), nil
}

// FluxStore stores file transfers. Every transition is conditional on the
// current state and the acting node, so a replayed or concurrent request
// cannot skip a step or act for a peer.
type FluxStore interface {
	// CreateFluxTransfer stores the sender's offer in pending state. It
	// assigns ID, CreatedAt, UpdatedAt and ExpiresAt (the caller sets the
	// rest) and fails with [ErrFluxQuota] when an active-transfer limit would
	// be exceeded.
	CreateFluxTransfer(t *FluxTransfer, quotas FluxQuotas) error
	// GetFluxTransfer returns a transfer by ID.
	GetFluxTransfer(id string) (FluxTransfer, bool)
	// ListFluxTransfers returns every transfer the node is part of, newest
	// first.
	ListFluxTransfers(node NodeID) []FluxTransfer
	// ListAllFluxTransfers returns every transfer, newest first. It backs the
	// read-only management surface (spec section 33), which sees both sides
	// of every transfer of this organization. Content is never part of the
	// record.
	ListAllFluxTransfers() []FluxTransfer
	// AcceptFluxTransfer moves pending to accepted, recording the recipient's
	// per-transfer public key.
	AcceptFluxTransfer(id string, recipient NodeID, publicKey []byte) (FluxTransfer, error)
	// DenyFluxTransfer moves pending to denied.
	DenyFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error)
	// CancelFluxTransfer moves pending or accepted to cancelled.
	CancelFluxTransfer(id string, sender NodeID) (FluxTransfer, error)
	// UploadFluxTransfer moves accepted to uploaded.
	UploadFluxTransfer(id string, sender NodeID) (FluxTransfer, error)
	// CompleteFluxTransfer moves uploaded to completed: the recipient
	// confirmed the content.
	CompleteFluxTransfer(id string, recipient NodeID) (FluxTransfer, error)
	// FailFluxTransfer moves accepted or uploaded to failed.
	FailFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error)
	// ExpireFluxTransfers marks every active transfer past now as expired and
	// returns the affected records so the caller can delete their content.
	ExpireFluxTransfers(now time.Time) ([]FluxTransfer, error)
	// PruneFluxTransfers removes terminal transfers last updated before
	// cutoff and returns them.
	PruneFluxTransfers(cutoff time.Time) ([]FluxTransfer, error)
	// FluxStoredBytes returns the total plaintext size of uploaded content.
	FluxStoredBytes() (int64, error)
}
