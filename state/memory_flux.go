package state

import (
	"fmt"
	"slices"
	"time"
)

// cloneFluxTransfer deep-copies a transfer so callers cannot mutate stored
// state (the recipient key is a slice).
func cloneFluxTransfer(t FluxTransfer) FluxTransfer {
	out := t
	if t.RecipientKey != nil {
		out.RecipientKey = slices.Clone(t.RecipientKey)
	}
	return out
}

// CreateFluxTransfer implements [FluxStore].
func (s *MemoryStore) CreateFluxTransfer(t *FluxTransfer, quotas FluxQuotas) error {
	if t == nil {
		return fmt.Errorf("state: flux transfer is nil")
	}
	if t.SenderNode == 0 || t.RecipientNode == 0 || t.SenderNode == t.RecipientNode {
		return fmt.Errorf("state: flux transfer needs two distinct nodes")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkFluxQuotasLocked(t, quotas); err != nil {
		return err
	}
	if t.ID == "" {
		id, err := NewFluxTransferID()
		if err != nil {
			return err
		}
		t.ID = id
	}
	if t.ExpiresAt.IsZero() {
		return fmt.Errorf("state: flux transfer needs an expiry")
	}

	now := time.Now().UTC()
	t.State = FluxPending
	t.CreatedAt = now
	t.UpdatedAt = now
	t.ExpiresAt = t.ExpiresAt.UTC()
	s.flux[t.ID] = cloneFluxTransfer(*t)
	return nil
}

// checkFluxQuotasLocked enforces [FluxQuotas]; the caller holds the lock.
func (s *MemoryStore) checkFluxQuotasLocked(t *FluxTransfer, quotas FluxQuotas) error {
	active, total := 0, 0
	var stored int64
	for _, other := range s.flux {
		if !other.State.Active() {
			continue
		}
		total++
		if other.SenderNode == t.SenderNode || other.RecipientNode == t.SenderNode {
			active++
		}
	}
	for _, other := range s.flux {
		if other.State == FluxUploaded {
			stored += other.Size
		}
	}
	if quotas.MaxActivePerNode > 0 && active >= quotas.MaxActivePerNode {
		return fmt.Errorf("%w: node has %d active transfers", ErrFluxQuota, active)
	}
	if quotas.MaxActiveTotal > 0 && total >= quotas.MaxActiveTotal {
		return fmt.Errorf("%w: organization has %d active transfers", ErrFluxQuota, total)
	}
	if quotas.MaxStoredBytes > 0 && stored+t.Size > quotas.MaxStoredBytes {
		return fmt.Errorf("%w: %d stored bytes", ErrFluxQuota, stored)
	}
	return nil
}

// GetFluxTransfer implements [FluxStore].
func (s *MemoryStore) GetFluxTransfer(id string) (FluxTransfer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.flux[id]
	if !ok {
		return FluxTransfer{}, false
	}
	return cloneFluxTransfer(t), true
}

// ListFluxTransfers implements [FluxStore].
func (s *MemoryStore) ListFluxTransfers(node NodeID) []FluxTransfer {
	return s.listFluxTransfers(node, false)
}

// ListAllFluxTransfers implements [FluxStore].
func (s *MemoryStore) ListAllFluxTransfers() []FluxTransfer {
	return s.listFluxTransfers(0, true)
}

// listFluxTransfers returns cloned transfers newest first; all includes the
// transfers of nodes other than node (used by the management surface).
func (s *MemoryStore) listFluxTransfers(node NodeID, all bool) []FluxTransfer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []FluxTransfer
	for _, t := range s.flux {
		if !all && t.SenderNode != node && t.RecipientNode != node {
			continue
		}
		out = append(out, cloneFluxTransfer(t))
	}
	slices.SortFunc(out, func(a, b FluxTransfer) int {
		switch {
		case a.CreatedAt.After(b.CreatedAt):
			return -1
		case a.CreatedAt.Before(b.CreatedAt):
			return 1
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})
	return out
}

// transitionFluxTransfer applies one conditional state change; the caller
// holds the lock.
func (s *MemoryStore) transitionFluxTransfer(action string, id string, actor NodeID,
	role fluxRole, from []FluxTransferState, to FluxTransferState, reason string, key []byte) (FluxTransfer, error) {

	current, ok := s.flux[id]
	if !ok {
		return FluxTransfer{}, ErrFluxTransferNotFound
	}
	actingNode := current.RecipientNode
	if role == fluxSenderRole {
		actingNode = current.SenderNode
	}
	if actingNode != actor {
		return FluxTransfer{}, ErrFluxTransferNotFound
	}
	if !slices.Contains(from, current.State) {
		return FluxTransfer{}, fmt.Errorf("%w: state is %s", ErrFluxTransferState, current.State)
	}

	current.State = to
	current.UpdatedAt = time.Now().UTC()
	current.Reason = reason
	if key != nil {
		current.RecipientKey = slices.Clone(key)
	}
	s.flux[id] = cloneFluxTransfer(current)
	return cloneFluxTransfer(current), nil
}

// AcceptFluxTransfer implements [FluxStore].
func (s *MemoryStore) AcceptFluxTransfer(id string, recipient NodeID, publicKey []byte) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("accepting", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxPending}, FluxAccepted, "", publicKey)
}

// DenyFluxTransfer implements [FluxStore].
func (s *MemoryStore) DenyFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("denying", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxPending}, FluxDenied, reason, nil)
}

// CancelFluxTransfer implements [FluxStore].
func (s *MemoryStore) CancelFluxTransfer(id string, sender NodeID) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("cancelling", id, sender, fluxSenderRole,
		[]FluxTransferState{FluxPending, FluxAccepted}, FluxCancelled, "", nil)
}

// UploadFluxTransfer implements [FluxStore].
func (s *MemoryStore) UploadFluxTransfer(id string, sender NodeID) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("uploading", id, sender, fluxSenderRole,
		[]FluxTransferState{FluxAccepted}, FluxUploaded, "", nil)
}

// CompleteFluxTransfer implements [FluxStore].
func (s *MemoryStore) CompleteFluxTransfer(id string, recipient NodeID) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("completing", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxUploaded}, FluxCompleted, "", nil)
}

// FailFluxTransfer implements [FluxStore].
func (s *MemoryStore) FailFluxTransfer(id string, recipient NodeID, reason string) (FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionFluxTransfer("failing", id, recipient, fluxRecipientRole,
		[]FluxTransferState{FluxAccepted, FluxUploaded}, FluxFailed, reason, nil)
}

// ExpireFluxTransfers implements [FluxStore].
func (s *MemoryStore) ExpireFluxTransfers(now time.Time) ([]FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []FluxTransfer
	for id, t := range s.flux {
		if !t.State.Active() || now.Before(t.ExpiresAt) {
			continue
		}
		t.State = FluxExpired
		t.UpdatedAt = now.UTC()
		s.flux[id] = cloneFluxTransfer(t)
		expired = append(expired, cloneFluxTransfer(t))
	}
	slices.SortFunc(expired, func(a, b FluxTransfer) int {
		if a.ID < b.ID {
			return -1
		} else if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return expired, nil
}

// PruneFluxTransfers implements [FluxStore].
func (s *MemoryStore) PruneFluxTransfers(cutoff time.Time) ([]FluxTransfer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pruned []FluxTransfer
	for id, t := range s.flux {
		if t.State.Active() || !t.UpdatedAt.Before(cutoff) {
			continue
		}
		pruned = append(pruned, cloneFluxTransfer(t))
		delete(s.flux, id)
	}
	slices.SortFunc(pruned, func(a, b FluxTransfer) int {
		if a.ID < b.ID {
			return -1
		} else if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return pruned, nil
}

// FluxStoredBytes implements [FluxStore].
func (s *MemoryStore) FluxStoredBytes() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stored int64
	for _, t := range s.flux {
		if t.State == FluxUploaded {
			stored += t.Size
		}
	}
	return stored, nil
}
