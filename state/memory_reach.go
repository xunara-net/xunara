package state

import (
	"time"
)

// CreateReachSession implements [ReachStore].
func (s *MemoryStore) CreateReachSession(session *ReachSession, quotas ReachQuotas) error {
	if err := validateReachSession(session); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[session.Sender]; !ok {
		return errUnknownNode(session.Sender)
	}
	if _, ok := s.byID[session.Target]; !ok {
		return errUnknownNode(session.Target)
	}
	active := 0
	for _, existing := range s.reach {
		if existing.Sender == session.Sender && existing.Target == session.Target && existing.State.Active() {
			active++
		}
	}
	if active >= quotas.maxActivePerPair() {
		return ErrReachSessionQuota
	}

	stored := *session
	if stored.State == "" {
		stored.State = ReachOffered
	}
	if stored.ID == "" {
		id, err := NewReachSessionID()
		if err != nil {
			return err
		}
		stored.ID = id
	}
	if _, exists := s.reach[stored.ID]; exists {
		return ErrReachSessionState
	}
	now := time.Now().UTC()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	if stored.ExpiresAt.IsZero() {
		stored.ExpiresAt = stored.CreatedAt.Add(ReachMaxOfferAge)
	}
	stored.UpdatedAt = stored.CreatedAt
	stored.Argv = append([]string(nil), stored.Argv...)

	s.reach[stored.ID] = stored
	*session = copyReachSession(stored)
	return nil
}

// GetReachSession implements [ReachStore].
func (s *MemoryStore) GetReachSession(id string) (ReachSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.reach[id]
	if !ok {
		return ReachSession{}, false
	}
	return copyReachSession(session), true
}

// ListReachSessions implements [ReachStore]. Newest first.
func (s *MemoryStore) ListReachSessions(nodeID NodeID) []ReachSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ReachSession, 0, len(s.reach))
	for _, session := range s.reach {
		if session.Sender == nodeID || session.Target == nodeID {
			out = append(out, copyReachSession(session))
		}
	}
	sortReachSessions(out)
	return out
}

// SetReachSessionState implements [ReachStore].
func (s *MemoryStore) SetReachSessionState(id string, from, to ReachState, now time.Time) (bool, error) {
	if !from.Valid() || !to.Valid() {
		return false, ErrReachSessionState
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.reach[id]
	if !ok {
		return false, ErrReachSessionNotFound
	}
	if session.State != from {
		return false, nil
	}
	session.State = to
	session.UpdatedAt = now.UTC()
	s.reach[id] = session
	return true, nil
}

// StartReachSession implements [ReachStore].
func (s *MemoryStore) StartReachSession(id string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.reach[id]
	if !ok {
		return false, ErrReachSessionNotFound
	}
	if session.State != ReachAccepted {
		return false, nil
	}
	session.State = ReachRunning
	session.UpdatedAt = now.UTC()
	session.ExpiresAt = expiresAt.UTC()
	s.reach[id] = session
	return true, nil
}

// FinishReachSession implements [ReachStore].
func (s *MemoryStore) FinishReachSession(id string, exitCode int, errText string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.reach[id]
	if !ok {
		return false, ErrReachSessionNotFound
	}
	if session.State != ReachRunning {
		return false, nil
	}
	if exitCode == 0 && errText == "" {
		session.State = ReachSucceeded
	} else {
		session.State = ReachFailed
	}
	session.ExitCode = &exitCode
	session.Error = truncateReachError(errText)
	session.UpdatedAt = now.UTC()
	s.reach[id] = session
	return true, nil
}

// AppendReachChunk implements [ReachStore].
func (s *MemoryStore) AppendReachChunk(id, stream string, seq int64, data []byte, maxTotal int64, now time.Time) error {
	if err := validateReachChunk(stream, seq, data, maxTotal); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.reach[id]
	if !ok {
		return ErrReachSessionNotFound
	}
	if session.State != ReachRunning {
		return ErrReachSessionState
	}
	chunks := s.reachChunks[id]
	var total int64
	for _, byStream := range chunks {
		for _, chunk := range byStream {
			total += int64(len(chunk.Data))
		}
	}
	if total+int64(len(data)) > maxTotal {
		return ErrReachOutputLimit
	}
	for _, chunk := range chunks[stream] {
		if chunk.Seq == seq {
			return ErrReachChunkDuplicate
		}
	}

	if chunks == nil {
		chunks = make(map[string][]ReachChunk)
		s.reachChunks[id] = chunks
	}
	chunks[stream] = append(chunks[stream], ReachChunk{
		Stream:    stream,
		Seq:       seq,
		Data:      append([]byte(nil), data...),
		CreatedAt: now.UTC(),
	})
	return nil
}

// ReachChunks implements [ReachStore].
func (s *MemoryStore) ReachChunks(id, stream string, after int64, limit int) ([]ReachChunk, error) {
	if !ReachChunkStreamValid(stream) || limit <= 0 || limit > ReachMaxChunksPerRead {
		return nil, ErrReachSessionState
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.reach[id]; !ok {
		return nil, ErrReachSessionNotFound
	}
	var out []ReachChunk
	for _, chunk := range s.reachChunks[id][stream] {
		if chunk.Seq <= after {
			continue
		}
		out = append(out, ReachChunk{
			Stream:    chunk.Stream,
			Seq:       chunk.Seq,
			Data:      append([]byte(nil), chunk.Data...),
			CreatedAt: chunk.CreatedAt,
		})
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// ExpireReachSessions implements [ReachStore].
func (s *MemoryStore) ExpireReachSessions(now time.Time) ([]ReachSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []ReachSession
	for id, session := range s.reach {
		if !session.State.Active() || now.UTC().Before(session.ExpiresAt) {
			continue
		}
		session.State = ReachExpired
		session.UpdatedAt = now.UTC()
		s.reach[id] = session
		expired = append(expired, copyReachSession(session))
	}
	sortReachSessions(expired)
	return expired, nil
}

// DeleteReachSessions implements [ReachStore].
func (s *MemoryStore) DeleteReachSessions(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, session := range s.reach {
		if session.State.Active() || !session.UpdatedAt.Before(before) {
			continue
		}
		delete(s.reach, id)
		delete(s.reachChunks, id)
		removed++
	}
	return removed, nil
}
