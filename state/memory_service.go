package state

import (
	"slices"
	"time"
)

// ReplaceNodeServices implements [ServiceStore].
func (s *MemoryStore) ReplaceNodeServices(id NodeID, services []Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[id]; !ok {
		return errUnknownNode(id)
	}

	now := time.Now().UTC()
	existing := make(map[string]time.Time)
	for name, svc := range s.services {
		if svc.NodeID == id {
			existing[name] = svc.Created
		}
	}

	// Apply the replacement only after every name passed the ownership check,
	// so a conflict cannot leave the node with half a set.
	next := make(map[string]Service, len(services))
	for _, svc := range services {
		if _, duplicate := next[svc.Name]; duplicate {
			return errServiceNameTaken(svc.Name)
		}
		if other, ok := s.services[svc.Name]; ok && other.NodeID != id {
			return errServiceNameTaken(svc.Name)
		}
		if prev, ok := existing[svc.Name]; ok {
			svc.Created = prev
		}
		if svc.Created.IsZero() {
			svc.Created = now
		}
		svc.NodeID = id
		svc.Updated = now
		next[svc.Name] = svc
	}

	for name, svc := range s.services {
		if svc.NodeID == id {
			delete(s.services, name)
		}
	}
	for name, svc := range next {
		s.services[name] = svc
	}
	return nil
}

// ListServices implements [ServiceStore].
func (s *MemoryStore) ListServices() []Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Service, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, copyService(svc))
	}
	slices.SortFunc(out, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	return out
}

// ServicesForNode implements [ServiceStore].
func (s *MemoryStore) ServicesForNode(id NodeID) ([]Service, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := []Service{}
	for _, svc := range s.services {
		if svc.NodeID == id {
			out = append(out, copyService(svc))
		}
	}
	slices.SortFunc(out, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	return out, nil
}

// GetServiceByName implements [ServiceStore].
func (s *MemoryStore) GetServiceByName(name string) (Service, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svc, ok := s.services[name]
	if !ok {
		return Service{}, false
	}
	return copyService(svc), true
}

// NodeServiceCounts implements [ServiceStore].
func (s *MemoryStore) NodeServiceCounts() (map[NodeID]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[NodeID]int)
	for _, svc := range s.services {
		counts[svc.NodeID]++
	}
	return counts, nil
}

// copyService returns a copy that shares no mutable state with the store.
func copyService(svc Service) Service {
	out := svc
	if len(svc.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(svc.Metadata))
		for k, v := range svc.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}
