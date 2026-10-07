package state

import (
	"slices"
	"sort"
	"time"
)

// CreatePreAuthKey implements [PreAuthKeyStore].
func (s *MemoryStore) CreatePreAuthKey(k *PreAuthKey) error {
	if k == nil || k.Key == "" {
		return errPreAuthKeyRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.preauth[k.Key]; ok {
		return ErrPreAuthKeyExists
	}

	k.ID = s.nextKeyID
	s.nextKeyID++
	if k.Created.IsZero() {
		k.Created = time.Now().UTC()
	}
	k.Tags = slices.Clone(k.Tags)

	s.preauth[k.Key] = *k
	return nil
}

// GetPreAuthKey implements [PreAuthKeyStore].
func (s *MemoryStore) GetPreAuthKey(secret string) (PreAuthKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.preauth[secret]
	k.Tags = slices.Clone(k.Tags)
	return k, ok
}

// ListPreAuthKeys implements [PreAuthKeyStore].
func (s *MemoryStore) ListPreAuthKeys() []PreAuthKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]PreAuthKey, 0, len(s.preauth))
	for _, k := range s.preauth {
		k.Tags = slices.Clone(k.Tags)
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// MarkPreAuthKeyUsed implements [PreAuthKeyStore].
func (s *MemoryStore) MarkPreAuthKeyUsed(secret string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.preauth[secret]
	if !ok {
		return errPreAuthKeyNotFound
	}

	k.Used = true
	used := at.UTC()
	k.UsedAt = &used

	s.preauth[secret] = k
	return nil
}

// DeletePreAuthKey implements [PreAuthKeyStore].
func (s *MemoryStore) DeletePreAuthKey(secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.preauth, secret)
	return nil
}
