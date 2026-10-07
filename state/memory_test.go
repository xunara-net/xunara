package state

import (
	"sync"
	"testing"

	"tailscale.com/types/key"
)

func TestMemoryStoreConformance(t *testing.T) {
	runStoreConformance(t, func(*testing.T) Store { return NewMemoryStore() })
}

func TestMemoryPreAuthKeyConformance(t *testing.T) {
	runPreAuthKeyConformance(t, func(*testing.T) Store { return NewMemoryStore() })
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	s := NewMemoryStore()

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			n := Node{NodeKey: key.NewNode().Public()}
			if err := s.CreateNode(&n); err != nil {
				t.Errorf("CreateNode: %v", err)
				return
			}
			if _, ok := s.GetNodeByNodeKey(n.NodeKey); !ok {
				t.Error("node not found right after creation")
			}
			_ = s.ListNodes()
		}()
	}
	wg.Wait()

	if got := len(s.ListNodes()); got != 32 {
		t.Errorf("ListNodes len = %d, want 32", got)
	}
}
