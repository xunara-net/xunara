package identity

import "testing"

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
