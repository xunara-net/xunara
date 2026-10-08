package state

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"
)

// reachTestSession builds an offered session that passes validation.
func reachTestSession(sender, target NodeID) ReachSession {
	return ReachSession{
		Sender:  sender,
		Target:  target,
		Argv:    []string{"uptime"},
		Timeout: time.Minute,
	}
}

// runReachConformance exercises the [ReachStore] contract. Both
// implementations must pass it.
func runReachConformance(t *testing.T, newStore storeFactory) {
	t.Run("lifecycle with compare-and-set transitions", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		if session.ID == "" || session.State != ReachOffered || session.CreatedAt.IsZero() {
			t.Fatalf("created session = %+v", session)
		}
		got, ok := s.GetReachSession(session.ID)
		if !ok || got.Sender != first.ID || got.Target != second.ID || len(got.Argv) != 1 {
			t.Fatalf("GetReachSession = %+v, %v", got, ok)
		}
		if got.ExpiresAt.Before(got.CreatedAt.Add(ReachMaxOfferAge - time.Second)) {
			t.Errorf("offer deadline = %v, want about %v after creation", got.ExpiresAt, ReachMaxOfferAge)
		}
		for _, node := range []NodeID{first.ID, second.ID} {
			if list := s.ListReachSessions(node); len(list) != 1 || list[0].ID != session.ID {
				t.Errorf("ListReachSessions(%d) = %+v", node, list)
			}
		}
		if list := s.ListReachSessions(NodeID(999)); len(list) != 0 {
			t.Errorf("unrelated node sees %+v", list)
		}

		if ok, err := s.SetReachSessionState(session.ID, ReachOffered, ReachAccepted, time.Now()); err != nil || !ok {
			t.Fatalf("accept = %v/%v", ok, err)
		}
		if ok, err := s.SetReachSessionState(session.ID, ReachOffered, ReachAccepted, time.Now()); err != nil || ok {
			t.Fatalf("second accept = %v/%v, want a failed compare-and-set", ok, err)
		}
		if ok, err := s.StartReachSession(session.ID, time.Now().Add(time.Minute), time.Now()); err != nil || !ok {
			t.Fatalf("start = %v/%v", ok, err)
		}
		if ok, err := s.StartReachSession(session.ID, time.Now(), time.Now()); err != nil || ok {
			t.Fatalf("second start = %v/%v", ok, err)
		}

		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 0, []byte("up "), ReachMaxOutputBytes, time.Now()); err != nil {
			t.Fatalf("AppendReachChunk: %v", err)
		}
		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 1, []byte("1 day\n"), ReachMaxOutputBytes, time.Now()); err != nil {
			t.Fatalf("AppendReachChunk: %v", err)
		}
		if err := s.AppendReachChunk(session.ID, ReachStreamStderr, 0, []byte("warn\n"), ReachMaxOutputBytes, time.Now()); err != nil {
			t.Fatalf("AppendReachChunk: %v", err)
		}
		chunks, err := s.ReachChunks(session.ID, ReachStreamStdout, 0, ReachMaxChunksPerRead)
		if err != nil || len(chunks) != 1 || string(chunks[0].Data) != "1 day\n" {
			t.Fatalf("ReachChunks after 0 = %+v (%v)", chunks, err)
		}
		if chunks, err = s.ReachChunks(session.ID, ReachStreamStderr, -1, 1); err != nil || len(chunks) != 1 || string(chunks[0].Data) != "warn\n" {
			t.Fatalf("ReachChunks stderr = %+v (%v)", chunks, err)
		}

		if ok, err := s.FinishReachSession(session.ID, 0, "", time.Now()); err != nil || !ok {
			t.Fatalf("finish = %v/%v", ok, err)
		}
		got, _ = s.GetReachSession(session.ID)
		if got.State != ReachSucceeded || got.ExitCode == nil || *got.ExitCode != 0 {
			t.Fatalf("finished session = %+v", got)
		}
		if ok, err := s.FinishReachSession(session.ID, 0, "", time.Now()); err != nil || ok {
			t.Fatalf("second finish = %v/%v", ok, err)
		}
	})

	t.Run("failure carries the exit code and static error", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		if ok, _ := s.SetReachSessionState(session.ID, ReachOffered, ReachAccepted, time.Now()); !ok {
			t.Fatal("accept failed")
		}
		if ok, _ := s.StartReachSession(session.ID, time.Now().Add(time.Minute), time.Now()); !ok {
			t.Fatal("start failed")
		}
		if ok, err := s.FinishReachSession(session.ID, 3, "exit status 3", time.Now()); err != nil || !ok {
			t.Fatalf("finish = %v/%v", ok, err)
		}
		got, _ := s.GetReachSession(session.ID)
		if got.State != ReachFailed || got.ExitCode == nil || *got.ExitCode != 3 || got.Error != "exit status 3" {
			t.Fatalf("failed session = %+v", got)
		}
	})

	t.Run("chunks are append-only, bounded and typed", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}

		// Output before the command runs is refused.
		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 0, []byte("x"), ReachMaxOutputBytes, time.Now()); !errors.Is(err, ErrReachSessionState) {
			t.Fatalf("chunk before start error = %v, want ErrReachSessionState", err)
		}

		if ok, _ := s.SetReachSessionState(session.ID, ReachOffered, ReachAccepted, time.Now()); !ok {
			t.Fatal("accept failed")
		}
		if ok, _ := s.StartReachSession(session.ID, time.Now().Add(time.Minute), time.Now()); !ok {
			t.Fatal("start failed")
		}

		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 0, []byte("first"), ReachMaxOutputBytes, time.Now()); err != nil {
			t.Fatalf("AppendReachChunk: %v", err)
		}
		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 0, []byte("duplicate"), ReachMaxOutputBytes, time.Now()); !errors.Is(err, ErrReachChunkDuplicate) {
			t.Fatalf("duplicate error = %v, want ErrReachChunkDuplicate", err)
		}
		if err := s.AppendReachChunk(session.ID, "stdin", 1, []byte("x"), ReachMaxOutputBytes, time.Now()); !errors.Is(err, ErrReachSessionState) {
			t.Fatalf("unknown stream error = %v, want ErrReachSessionState", err)
		}
		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 1, bytes.Repeat([]byte("x"), ReachMaxChunkBytes+1), ReachMaxOutputBytes, time.Now()); !errors.Is(err, ErrReachSessionState) {
			t.Fatalf("oversized chunk error = %v, want ErrReachSessionState", err)
		}
		if err := s.AppendReachChunk(session.ID, ReachStreamStdout, 2, []byte("0123456789"), 5, time.Now()); !errors.Is(err, ErrReachOutputLimit) {
			t.Fatalf("cap error = %v, want ErrReachOutputLimit", err)
		}
		if chunks, err := s.ReachChunks(session.ID, ReachStreamStdout, -1, ReachMaxChunksPerRead); err != nil || len(chunks) != 1 || string(chunks[0].Data) != "first" {
			t.Fatalf("chunks after rejected appends = %+v (%v)", chunks, err)
		}
		if _, err := s.ReachChunks(session.ID, ReachStreamStdout, 0, 0); !errors.Is(err, ErrReachSessionState) {
			t.Fatalf("zero-limit read error = %v", err)
		}
	})

	t.Run("pair quota bounds concurrent sessions", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")
		quotas := ReachQuotas{MaxActivePerPair: 2}

		for i := 0; i < 2; i++ {
			session := reachTestSession(first.ID, second.ID)
			if err := s.CreateReachSession(&session, quotas); err != nil {
				t.Fatalf("CreateReachSession %d: %v", i+1, err)
			}
			if i == 0 {
				if ok, _ := s.SetReachSessionState(session.ID, ReachOffered, ReachDenied, time.Now()); !ok {
					t.Fatal("deny failed")
				}
			}
		}

		// One was denied, so one slot is free; the next create succeeds and
		// the one after that hits the quota.
		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, quotas); err != nil {
			t.Fatalf("CreateReachSession after terminal session: %v", err)
		}
		blocked := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&blocked, quotas); !errors.Is(err, ErrReachSessionQuota) {
			t.Fatalf("over-quota error = %v, want ErrReachSessionQuota", err)
		}
		// The reverse direction has its own bucket.
		reverse := reachTestSession(second.ID, first.ID)
		if err := s.CreateReachSession(&reverse, quotas); err != nil {
			t.Fatalf("reverse direction: %v", err)
		}
	})

	t.Run("expiry moves active sessions to expired once", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")
		now := time.Now().UTC()

		session := reachTestSession(first.ID, second.ID)
		session.ExpiresAt = now.Add(-time.Minute)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		fresh := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&fresh, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}

		expired, err := s.ExpireReachSessions(now)
		if err != nil || len(expired) != 1 || expired[0].ID != session.ID || expired[0].State != ReachExpired {
			t.Fatalf("ExpireReachSessions = %+v (%v)", expired, err)
		}
		if again, err := s.ExpireReachSessions(now); err != nil || len(again) != 0 {
			t.Fatalf("second ExpireReachSessions = %+v (%v)", again, err)
		}
		if got, _ := s.GetReachSession(fresh.ID); got.State != ReachOffered {
			t.Errorf("fresh session = %+v", got)
		}
		if ok, _ := s.SetReachSessionState(session.ID, ReachOffered, ReachAccepted, now); ok {
			t.Error("an expired session accepted a late accept")
		}
	})

	t.Run("delete removes terminal sessions and their chunks", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		if ok, _ := s.SetReachSessionState(session.ID, ReachOffered, ReachDenied, time.Now()); !ok {
			t.Fatal("deny failed")
		}
		if _, err := s.DeleteReachSessions(time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("DeleteReachSessions: %v", err)
		}
		if _, ok := s.GetReachSession(session.ID); ok {
			t.Error("terminal session survived the delete")
		}

		active := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&active, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		removed, err := s.DeleteReachSessions(time.Now().Add(time.Hour))
		if err != nil || removed != 0 {
			t.Fatalf("delete with an active session = %d/%v", removed, err)
		}
	})

	t.Run("creation validates the shape", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		cases := map[string]ReachSession{
			"no argv":       {Sender: first.ID, Target: second.ID, Timeout: time.Minute},
			"empty arg":     {Sender: first.ID, Target: second.ID, Argv: []string{"ls", ""}, Timeout: time.Minute},
			"args too long": {Sender: first.ID, Target: second.ID, Argv: []string{string(make([]byte, ReachMaxArgBytes+1))}, Timeout: time.Minute},
			"too many args": {Sender: first.ID, Target: second.ID, Argv: make([]string, ReachMaxArgvEntries+1), Timeout: time.Minute},
			"no timeout":    {Sender: first.ID, Target: second.ID, Argv: []string{"ls"}},
			"over timeout":  {Sender: first.ID, Target: second.ID, Argv: []string{"ls"}, Timeout: ReachMaxTimeout + time.Second},
			"self":          {Sender: first.ID, Target: first.ID, Argv: []string{"ls"}, Timeout: time.Minute},
		}
		for name, session := range cases {
			if err := s.CreateReachSession(&session, ReachQuotas{}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
		missing := ReachSession{Sender: first.ID, Target: NodeID(999), Argv: []string{"ls"}, Timeout: time.Minute}
		if err := s.CreateReachSession(&missing, ReachQuotas{}); err == nil {
			t.Error("a session to an unknown node was accepted")
		}
	})

	t.Run("returned sessions are copies", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		session := reachTestSession(first.ID, second.ID)
		if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
			t.Fatalf("CreateReachSession: %v", err)
		}
		got, _ := s.GetReachSession(session.ID)
		got.Argv[0] = "tampered"
		if again, _ := s.GetReachSession(session.ID); !slices.Equal(again.Argv, []string{"uptime"}) {
			t.Errorf("stored argv = %v", again.Argv)
		}
	})
}

func TestMemoryReachConformance(t *testing.T) {
	runReachConformance(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestSQLiteReachConformance(t *testing.T) {
	runReachConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, t.TempDir()+"/state.db")
	})
}

// TestReachSessionIDsAreRandom checks that IDs do not collide across stores
// (they are the only handle both sides exchange).
func TestReachSessionIDsAreRandom(t *testing.T) {
	seen := make(map[string]bool)
	for range 64 {
		id, err := NewReachSessionID()
		if err != nil {
			t.Fatalf("NewReachSessionID: %v", err)
		}
		if len(id) != 24 || seen[id] {
			t.Fatalf("id = %q (seen=%v)", id, seen[id])
		}
		seen[id] = true
	}
}

// TestSQLiteReachCascade checks that deleting nodes removes their sessions.
func TestSQLiteReachCascade(t *testing.T) {
	s := openTestSQLite(t, t.TempDir()+"/state.db")
	first := createTestNode(t, s, "first")
	second := createTestNode(t, s, "second")

	session := reachTestSession(first.ID, second.ID)
	if err := s.CreateReachSession(&session, ReachQuotas{}); err != nil {
		t.Fatalf("CreateReachSession: %v", err)
	}
	if err := s.DeleteNode(second.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, ok := s.GetReachSession(session.ID); ok {
		t.Error("session survived its target's deletion")
	}
	if _, ok := s.GetNodeByNodeKey(first.NodeKey); !ok {
		t.Error("sender did not survive")
	}
}
