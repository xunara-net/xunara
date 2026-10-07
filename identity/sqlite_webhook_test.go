package identity

import (
	"testing"
	"time"
)

// TestWebhookCursorRoundTrip checks the durable cursor that makes webhook
// delivery restart-safe.
func TestWebhookCursorRoundTrip(t *testing.T) {
	s := openTestStore(t)

	if got := s.GetWebhookCursor("ops"); got != 0 {
		t.Fatalf("fresh cursor = %d, want 0", got)
	}

	for _, id := range []uint64{3, 7, 7} {
		if err := s.SetWebhookCursor("ops", id); err != nil {
			t.Fatalf("SetWebhookCursor(%d): %v", id, err)
		}
	}
	if got := s.GetWebhookCursor("ops"); got != 7 {
		t.Fatalf("cursor = %d, want 7", got)
	}
	if got := s.GetWebhookCursor("other"); got != 0 {
		t.Fatalf("other endpoint cursor = %d, want 0", got)
	}

	// A newer id must be able to move the cursor backwards too: operators may
	// reset an endpoint to replay history.
	if err := s.SetWebhookCursor("ops", 1); err != nil {
		t.Fatalf("SetWebhookCursor(1): %v", err)
	}
	if got := s.GetWebhookCursor("ops"); got != 1 {
		t.Fatalf("cursor after reset = %d, want 1", got)
	}
}

// TestListAuditAfter checks the cursor-ordered read the dispatcher depends on.
func TestListAuditAfter(t *testing.T) {
	s := openTestStore(t)

	for _, action := range []string{"user.created", "node.registered", "node.approved", "session.created"} {
		if err := s.AppendAudit(&AuditEvent{Action: action}); err != nil {
			t.Fatalf("AppendAudit(%s): %v", action, err)
		}
	}

	got := s.ListAuditAfter(0, 0)
	if len(got) != 4 {
		t.Fatalf("events = %d, want 4", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatalf("events not ordered by ID: %d then %d", got[i-1].ID, got[i].ID)
		}
	}

	after := s.ListAuditAfter(got[1].ID, 0)
	if len(after) != 2 || after[0].ID != got[2].ID {
		t.Fatalf("ListAuditAfter(%d) = %+v, want the last two events", got[1].ID, after)
	}

	limited := s.ListAuditAfter(0, 2)
	if len(limited) != 2 || limited[1].ID != got[1].ID {
		t.Fatalf("limited read = %+v, want the first two events", limited)
	}
}

// TestWebhookDeliveryLease covers the durable single-writer lease: one holder
// at a time, expiry-based takeover, renewal only by the owner, and release.
func TestWebhookDeliveryLease(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()

	ok, err := s.ClaimWebhookEndpoint("ops", "instance-a", now, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("first claim = %v, %v; want true", ok, err)
	}

	// A different instance cannot take a live lease, but the owner can renew
	// it and a renewed claim does not need re-claiming.
	ok, err = s.ClaimWebhookEndpoint("ops", "instance-b", now.Add(time.Second), now.Add(time.Minute))
	if err != nil || ok {
		t.Fatalf("second claim = %v, %v; want false while the lease is live", ok, err)
	}
	ok, err = s.ClaimWebhookEndpoint("ops", "instance-a", now.Add(time.Second), now.Add(2*time.Minute))
	if err != nil || !ok {
		t.Fatalf("owner re-claim = %v, %v; want true", ok, err)
	}
	if ok, err := s.RenewWebhookClaim("ops", "instance-b", now.Add(3*time.Minute)); err != nil || ok {
		t.Fatalf("renew by another instance = %v, %v; want false", ok, err)
	}
	if ok, err := s.RenewWebhookClaim("ops", "instance-a", now.Add(3*time.Minute)); err != nil || !ok {
		t.Fatalf("renew by owner = %v, %v; want true", ok, err)
	}

	// An expired lease is free for another instance to take.
	deadline := now.Add(4 * time.Minute)
	ok, err = s.ClaimWebhookEndpoint("ops", "instance-b", deadline, deadline.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("takeover after expiry = %v, %v; want true", ok, err)
	}

	// Releasing requires the owner; the old owner's release must not free the
	// new holder's lease.
	if err := s.ReleaseWebhookClaim("ops", "instance-a"); err != nil {
		t.Fatalf("release by non-owner: %v", err)
	}
	if ok, _ := s.ClaimWebhookEndpoint("ops", "instance-c", deadline, deadline.Add(time.Minute)); ok {
		t.Fatal("claim succeeded after a non-owner release")
	}
	if err := s.ReleaseWebhookClaim("ops", "instance-b"); err != nil {
		t.Fatalf("release by owner: %v", err)
	}
	if ok, err := s.ClaimWebhookEndpoint("ops", "instance-c", deadline, deadline.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("claim after release = %v, %v; want true", ok, err)
	}
}

// TestWebhookRetryState checks that the backoff survives restarts and can be
// cleared by a success.
func TestWebhookRetryState(t *testing.T) {
	s := openTestStore(t)

	if attempts, retryAt := s.WebhookRetryState("ops"); attempts != 0 || !retryAt.IsZero() {
		t.Fatalf("initial retry state = %d, %v; want zero", attempts, retryAt)
	}

	retryAt := time.Now().UTC().Add(30 * time.Second)
	if err := s.SetWebhookRetryState("ops", 3, retryAt); err != nil {
		t.Fatalf("SetWebhookRetryState: %v", err)
	}
	attempts, got := s.WebhookRetryState("ops")
	if attempts != 3 || !got.Equal(retryAt) {
		t.Fatalf("retry state = %d, %v; want 3, %v", attempts, got, retryAt)
	}

	// The retry state and the cursor share one row and do not clobber each
	// other.
	if err := s.SetWebhookCursor("ops", 42); err != nil {
		t.Fatalf("SetWebhookCursor: %v", err)
	}
	if attempts, _ := s.WebhookRetryState("ops"); attempts != 3 {
		t.Errorf("attempts = %d after a cursor update, want 3", attempts)
	}
	if got := s.GetWebhookCursor("ops"); got != 42 {
		t.Errorf("cursor = %d after a retry-state update, want 42", got)
	}

	if err := s.SetWebhookRetryState("ops", 0, time.Time{}); err != nil {
		t.Fatalf("clearing retry state: %v", err)
	}
	if attempts, retryAt := s.WebhookRetryState("ops"); attempts != 0 || !retryAt.IsZero() {
		t.Fatalf("cleared retry state = %d, %v; want zero", attempts, retryAt)
	}
	if got := s.GetWebhookCursor("ops"); got != 42 {
		t.Errorf("cursor = %d after clearing the retry state, want 42", got)
	}
}
