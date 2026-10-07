package state

import (
	"sort"
	"time"
)

// UpsertDNSRecord implements [DNSRecordStore].
func (s *MemoryStore) UpsertDNSRecord(r *DNSRecord) error {
	if r == nil || r.Name == "" {
		return errDNSRecordNameRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, existing := range s.dns {
		if existing.Name == r.Name && existing.Type == r.Type && existing.Value == r.Value {
			r.ID = id
			r.Created = existing.Created
			return nil
		}
	}

	r.ID = s.nextDNSID
	s.nextDNSID++
	if r.Created.IsZero() {
		r.Created = time.Now().UTC()
	}

	s.dns[r.ID] = *r
	return nil
}

// ListDNSRecords implements [DNSRecordStore].
func (s *MemoryStore) ListDNSRecords() []DNSRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]DNSRecord, 0, len(s.dns))
	for _, r := range s.dns {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteDNSRecord implements [DNSRecordStore].
func (s *MemoryStore) DeleteDNSRecord(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.dns, id)
	return nil
}
