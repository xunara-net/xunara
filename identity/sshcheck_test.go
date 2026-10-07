package identity

import (
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

// sshCheckFixture creates one pending session bound to (10, 20).
func sshCheckFixture(t *testing.T, s *SQLiteStore) SSHCheckSession {
	t.Helper()

	sess, err := s.CreateSSHCheckSession(NewSSHCheckOptions{
		SrcNodeID: 10,
		DstNodeID: 20,
		LocalUser: "root",
	})
	if err != nil {
		t.Fatalf("CreateSSHCheckSession: %v", err)
	}
	if sess.ID == "" || sess.Verdict != SSHCheckPending {
		t.Fatalf("session = %+v, want a pending session with an ID", sess)
	}
	return sess
}

func TestSSHCheckSessionLifecycle(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	sess := sshCheckFixture(t, s)

	got, ok := s.GetSSHCheckSession(sess.ID)
	if !ok || got.SrcNodeID != 10 || got.DstNodeID != 20 || got.LocalUser != "root" {
		t.Fatalf("GetSSHCheckSession = %+v, %v", got, ok)
	}
	if !got.Pending() || got.Expired(now) {
		t.Fatalf("session state = %+v, want pending and unexpired", got)
	}

	// A verdict cannot be consumed before one exists.
	if _, err := s.ConsumeSSHCheckVerdict(sess.ID, now); err != ErrSSHCheckPending {
		t.Errorf("ConsumeSSHCheckVerdict(pending) = %v, want ErrSSHCheckPending", err)
	}

	decided, err := s.DecideSSHCheckSession(sess.ID, SSHCheckAccepted, tailcfg.UserID(1), now)
	if err != nil {
		t.Fatalf("DecideSSHCheckSession: %v", err)
	}
	if decided.Verdict != SSHCheckAccepted || decided.DecidedBy != 1 || decided.DecidedAt.IsZero() {
		t.Errorf("decided = %+v", decided)
	}

	// A second decision is rejected: approvals are not replays.
	if _, err := s.DecideSSHCheckSession(sess.ID, SSHCheckRejected, tailcfg.UserID(1), now); err != ErrSSHCheckDecided {
		t.Errorf("DecideSSHCheckSession(again) = %v, want ErrSSHCheckDecided", err)
	}

	consumed, err := s.ConsumeSSHCheckVerdict(sess.ID, now)
	if err != nil {
		t.Fatalf("ConsumeSSHCheckVerdict: %v", err)
	}
	if consumed.Verdict != SSHCheckAccepted || consumed.ConsumedAt.IsZero() {
		t.Errorf("consumed = %+v", consumed)
	}

	// The verdict belongs to exactly one follow-up.
	if _, err := s.ConsumeSSHCheckVerdict(sess.ID, now); err != ErrSSHCheckConsumed {
		t.Errorf("second ConsumeSSHCheckVerdict = %v, want ErrSSHCheckConsumed", err)
	}
}

func TestSSHCheckSessionExpiry(t *testing.T) {
	s := openTestStore(t)
	sess, err := s.CreateSSHCheckSession(NewSSHCheckOptions{
		SrcNodeID: 1, DstNodeID: 2, LocalUser: "root", TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateSSHCheckSession: %v", err)
	}

	future := time.Now().UTC().Add(2 * time.Minute)
	if _, err := s.DecideSSHCheckSession(sess.ID, SSHCheckAccepted, 1, future); err != ErrSSHCheckExpired {
		t.Errorf("Decide after expiry = %v, want ErrSSHCheckExpired", err)
	}
	if _, err := s.ConsumeSSHCheckVerdict(sess.ID, future); err != ErrSSHCheckPending {
		t.Errorf("Consume after expiry = %v, want ErrSSHCheckPending", err)
	}

	deleted, err := s.DeleteExpiredSSHCheckSessions(future)
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteExpiredSSHCheckSessions = %d, %v; want 1", deleted, err)
	}
	if _, ok := s.GetSSHCheckSession(sess.ID); ok {
		t.Error("expired session still present")
	}
}

func TestSSHCheckSessionUnknownAndBadVerdict(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()

	if _, err := s.DecideSSHCheckSession("nope", SSHCheckAccepted, 1, now); err != ErrSSHCheckNotFound {
		t.Errorf("Decide(unknown) = %v, want ErrSSHCheckNotFound", err)
	}
	if _, err := s.ConsumeSSHCheckVerdict("nope", now); err != ErrSSHCheckNotFound {
		t.Errorf("Consume(unknown) = %v, want ErrSSHCheckNotFound", err)
	}

	sess := sshCheckFixture(t, s)
	if _, err := s.DecideSSHCheckSession(sess.ID, SSHCheckVerdict("maybe"), 1, now); err != ErrSSHCheckVerdict {
		t.Errorf("Decide(bad verdict) = %v, want ErrSSHCheckVerdict", err)
	}
	if _, err := s.CreateSSHCheckSession(NewSSHCheckOptions{DstNodeID: 2}); err == nil {
		t.Error("CreateSSHCheckSession without a source node succeeded")
	}
}

func TestSSHCheckAuthMemory(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()

	if _, ok := s.SSHCheckAuth(10, 20); ok {
		t.Fatal("SSHCheckAuth returned an approval that was never recorded")
	}

	if err := s.RecordSSHCheckAuth(10, 20, now); err != nil {
		t.Fatalf("RecordSSHCheckAuth: %v", err)
	}
	got, ok := s.SSHCheckAuth(10, 20)
	if !ok || !got.Equal(now) {
		t.Fatalf("SSHCheckAuth = %v, %v; want %v", got, ok, now)
	}

	later := now.Add(time.Hour)
	if err := s.RecordSSHCheckAuth(10, 20, later); err != nil {
		t.Fatalf("RecordSSHCheckAuth(again): %v", err)
	}
	if got, _ := s.SSHCheckAuth(10, 20); !got.Equal(later) {
		t.Errorf("SSHCheckAuth after update = %v, want %v", got, later)
	}
	if _, ok := s.SSHCheckAuth(20, 10); ok {
		t.Error("approvals must be directional: (20,10) must not match (10,20)")
	}

	if err := s.ClearSSHCheckAuth(); err != nil {
		t.Fatalf("ClearSSHCheckAuth: %v", err)
	}
	if _, ok := s.SSHCheckAuth(10, 20); ok {
		t.Error("SSHCheckAuth returned an approval after ClearSSHCheckAuth")
	}
}
