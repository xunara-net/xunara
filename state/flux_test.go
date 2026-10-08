package state

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// fluxOffer is a ready-to-store offer shared by the conformance subtests.
func fluxOffer(sender, recipient NodeID) *FluxTransfer {
	return &FluxTransfer{
		SenderNode:    sender,
		RecipientNode: recipient,
		Name:          "report.txt",
		Size:          128,
		SHA256:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ExpiresAt:     time.Now().Add(time.Hour),
	}
}

// runFluxConformance exercises the [FluxStore] contract. Both implementations
// must pass it.
func runFluxConformance(t *testing.T, newStore storeFactory) {
	t.Run("offer accept upload complete", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")
		other := createTestNode(t, s, "other")

		offer := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(offer, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		if offer.ID == "" || offer.State != FluxPending || offer.CreatedAt.IsZero() {
			t.Fatalf("stored offer = %+v", offer)
		}

		// Both parties see it; a third node does not.
		if got := s.ListFluxTransfers(sender.ID); len(got) != 1 || got[0].ID != offer.ID {
			t.Errorf("ListFluxTransfers(sender) = %+v", got)
		}
		if got := s.ListFluxTransfers(recipient.ID); len(got) != 1 || got[0].ID != offer.ID {
			t.Errorf("ListFluxTransfers(recipient) = %+v", got)
		}
		if got := s.ListFluxTransfers(other.ID); len(got) != 0 {
			t.Errorf("ListFluxTransfers(other) = %+v, want none", got)
		}

		// Only the recipient may accept; the sender cannot act as them.
		if _, err := s.AcceptFluxTransfer(offer.ID, sender.ID, []byte("key")); !errors.Is(err, ErrFluxTransferNotFound) {
			t.Fatalf("sender accepting = %v, want ErrFluxTransferNotFound", err)
		}
		accepted, err := s.AcceptFluxTransfer(offer.ID, recipient.ID, []byte("key"))
		if err != nil {
			t.Fatalf("AcceptFluxTransfer: %v", err)
		}
		if accepted.State != FluxAccepted || string(accepted.RecipientKey) != "key" {
			t.Errorf("accepted = %+v", accepted)
		}

		// Accepting twice is a state error, not a silent no-op.
		if _, err := s.AcceptFluxTransfer(offer.ID, recipient.ID, []byte("key2")); !errors.Is(err, ErrFluxTransferState) {
			t.Fatalf("second accept = %v, want ErrFluxTransferState", err)
		}
		// The recipient cannot upload, the sender can.
		if _, err := s.UploadFluxTransfer(offer.ID, recipient.ID); !errors.Is(err, ErrFluxTransferNotFound) {
			t.Fatalf("recipient uploading = %v, want ErrFluxTransferNotFound", err)
		}
		uploaded, err := s.UploadFluxTransfer(offer.ID, sender.ID)
		if err != nil {
			t.Fatalf("UploadFluxTransfer: %v", err)
		}
		if uploaded.State != FluxUploaded {
			t.Errorf("uploaded = %+v", uploaded)
		}
		completed, err := s.CompleteFluxTransfer(offer.ID, recipient.ID)
		if err != nil {
			t.Fatalf("CompleteFluxTransfer: %v", err)
		}
		if completed.State != FluxCompleted {
			t.Errorf("completed = %+v", completed)
		}
		if _, err := s.CompleteFluxTransfer(offer.ID, recipient.ID); !errors.Is(err, ErrFluxTransferState) {
			t.Fatalf("second complete = %v, want ErrFluxTransferState", err)
		}
	})

	t.Run("deny cancel and fail record static reasons", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")

		offer := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(offer, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		denied, err := s.DenyFluxTransfer(offer.ID, recipient.ID, "not wanted")
		if err != nil {
			t.Fatalf("DenyFluxTransfer: %v", err)
		}
		if denied.State != FluxDenied || denied.Reason != "not wanted" {
			t.Errorf("denied = %+v", denied)
		}
		if _, err := s.CancelFluxTransfer(offer.ID, sender.ID); !errors.Is(err, ErrFluxTransferState) {
			t.Fatalf("cancelling a denied transfer = %v, want ErrFluxTransferState", err)
		}

		cancelled := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(cancelled, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		if _, err := s.CancelFluxTransfer(cancelled.ID, recipient.ID); !errors.Is(err, ErrFluxTransferNotFound) {
			t.Fatalf("recipient cancelling = %v, want ErrFluxTransferNotFound", err)
		}
		if got, err := s.CancelFluxTransfer(cancelled.ID, sender.ID); err != nil || got.State != FluxCancelled {
			t.Fatalf("CancelFluxTransfer = %+v, %v", got, err)
		}

		failed := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(failed, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		if _, err := s.AcceptFluxTransfer(failed.ID, recipient.ID, []byte("k")); err != nil {
			t.Fatalf("AcceptFluxTransfer: %v", err)
		}
		got, err := s.FailFluxTransfer(failed.ID, recipient.ID, "could not decrypt")
		if err != nil {
			t.Fatalf("FailFluxTransfer: %v", err)
		}
		if got.State != FluxFailed || got.Reason != "could not decrypt" {
			t.Errorf("failed = %+v", got)
		}
	})

	t.Run("quotas bound active transfers and stored bytes", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")

		first := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(first, FluxQuotas{MaxActivePerNode: 1}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		second := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(second, FluxQuotas{MaxActivePerNode: 1}); !errors.Is(err, ErrFluxQuota) {
			t.Fatalf("second offer = %v, want ErrFluxQuota", err)
		}
		if err := s.CreateFluxTransfer(second, FluxQuotas{MaxActiveTotal: 1}); !errors.Is(err, ErrFluxQuota) {
			t.Fatalf("second offer (total quota) = %v, want ErrFluxQuota", err)
		}

		if _, err := s.AcceptFluxTransfer(first.ID, recipient.ID, []byte("k")); err != nil {
			t.Fatalf("AcceptFluxTransfer: %v", err)
		}
		if _, err := s.UploadFluxTransfer(first.ID, sender.ID); err != nil {
			t.Fatalf("UploadFluxTransfer: %v", err)
		}
		if stored, err := s.FluxStoredBytes(); err != nil || stored != first.Size {
			t.Errorf("FluxStoredBytes = %d, %v, want %d", stored, err, first.Size)
		}
		third := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(third, FluxQuotas{MaxStoredBytes: first.Size}); !errors.Is(err, ErrFluxQuota) {
			t.Fatalf("offer over the byte quota = %v, want ErrFluxQuota", err)
		}
	})

	t.Run("expiry and pruning", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")

		expiredOffer := fluxOffer(sender.ID, recipient.ID)
		expiredOffer.ExpiresAt = time.Now().Add(-time.Minute)
		if err := s.CreateFluxTransfer(expiredOffer, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		live := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(live, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}

		gone, err := s.ExpireFluxTransfers(time.Now())
		if err != nil {
			t.Fatalf("ExpireFluxTransfers: %v", err)
		}
		if len(gone) != 1 || gone[0].ID != expiredOffer.ID || gone[0].State != FluxExpired {
			t.Fatalf("expired = %+v, want the past-due offer", gone)
		}
		if got, _ := s.GetFluxTransfer(live.ID); got.State != FluxPending {
			t.Errorf("live transfer = %+v, want still pending", got)
		}
		// Terminal records are pruned once past the retention window.
		if pruned, err := s.PruneFluxTransfers(time.Now().Add(-time.Hour)); err != nil || len(pruned) != 0 {
			t.Errorf("PruneFluxTransfers(fresh cutoff) = %+v, %v, want none", pruned, err)
		}
		pruned, err := s.PruneFluxTransfers(time.Now().Add(time.Minute))
		if err != nil || len(pruned) != 1 || pruned[0].ID != expiredOffer.ID {
			t.Fatalf("PruneFluxTransfers = %+v, %v, want the expired offer", pruned, err)
		}
		if _, ok := s.GetFluxTransfer(expiredOffer.ID); ok {
			t.Error("pruned transfer is still readable")
		}
	})

	t.Run("management listing sees every participant", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")
		bystander := createTestNode(t, s, "bystander")

		first := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(first, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		second := fluxOffer(bystander.ID, sender.ID)
		if err := s.CreateFluxTransfer(second, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}

		// The management surface sees both sides of every transfer, while a
		// participant-wise listing only sees its own.
		all := s.ListAllFluxTransfers()
		if len(all) != 2 {
			t.Fatalf("ListAllFluxTransfers = %+v, want both transfers", all)
		}
		// Newest first; both were stored in the same nanosecond window, so
		// only the set and the ordering rule (created_at DESC, id) matter.
		ids := []string{all[0].ID, all[1].ID}
		if !slices.Contains(ids, first.ID) || !slices.Contains(ids, second.ID) {
			t.Errorf("management listing = %v, want %s and %s", ids, first.ID, second.ID)
		}
		if got := s.ListFluxTransfers(bystander.ID); len(got) != 1 || got[0].ID != second.ID {
			t.Errorf("participant listing = %+v", got)
		}
	})

	t.Run("deleting a node drops its transfers", func(t *testing.T) {
		s := newStore(t)
		sender := createTestNode(t, s, "sender")
		recipient := createTestNode(t, s, "recipient")
		bystander := createTestNode(t, s, "bystander")

		offer := fluxOffer(sender.ID, recipient.ID)
		if err := s.CreateFluxTransfer(offer, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}
		other := fluxOffer(bystander.ID, recipient.ID)
		if err := s.CreateFluxTransfer(other, FluxQuotas{}); err != nil {
			t.Fatalf("CreateFluxTransfer: %v", err)
		}

		if err := s.DeleteNode(sender.ID); err != nil {
			t.Fatalf("DeleteNode: %v", err)
		}
		if _, ok := s.GetFluxTransfer(offer.ID); ok {
			t.Error("transfer of a deleted node is still readable")
		}
		if _, ok := s.GetFluxTransfer(other.ID); !ok {
			t.Error("unrelated transfer was dropped")
		}
	})
}

// TestFluxRecipientKeyIsCopied checks that the recipient key a caller stores
// or reads shares no memory with the store.
func TestFluxRecipientKeyIsCopied(t *testing.T) {
	s := NewMemoryStore()
	sender := createTestNode(t, s, "sender")
	recipient := createTestNode(t, s, "recipient")

	offer := fluxOffer(sender.ID, recipient.ID)
	if err := s.CreateFluxTransfer(offer, FluxQuotas{}); err != nil {
		t.Fatalf("CreateFluxTransfer: %v", err)
	}
	key := []byte("recipient-key")
	accepted, err := s.AcceptFluxTransfer(offer.ID, recipient.ID, key)
	if err != nil {
		t.Fatalf("AcceptFluxTransfer: %v", err)
	}
	key[0] = 'X'
	if accepted.RecipientKey[0] != 'r' {
		t.Errorf("stored key aliases the caller's slice: %q", accepted.RecipientKey)
	}
	accepted.RecipientKey[0] = 'Y'
	again, _ := s.GetFluxTransfer(offer.ID)
	if again.RecipientKey[0] != 'r' {
		t.Errorf("read key aliases the caller's slice: %q", again.RecipientKey)
	}
}

// TestFluxStateValidity covers the state helper both implementations rely on.
func TestFluxStateValidity(t *testing.T) {
	for _, state := range []FluxTransferState{FluxPending, FluxAccepted, FluxUploaded} {
		if !state.Active() || !state.Valid() {
			t.Errorf("%s: Active=%v Valid=%v, want true/true", state, state.Active(), state.Valid())
		}
	}
	for _, state := range []FluxTransferState{FluxCompleted, FluxDenied, FluxFailed, FluxCancelled, FluxExpired} {
		if state.Active() || !state.Valid() {
			t.Errorf("%s: Active=%v Valid=%v, want false/true", state, state.Active(), state.Valid())
		}
	}
	if FluxTransferState("bogus").Valid() {
		t.Error("unknown state reported valid")
	}
	if !slices.Contains([]FluxTransferState{FluxPending}, FluxPending) {
		t.Error("sanity check failed")
	}
}

func TestMemoryFluxConformance(t *testing.T) {
	runFluxConformance(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestSQLiteFluxConformance(t *testing.T) {
	runFluxConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, t.TempDir()+"/state.db")
	})
}
