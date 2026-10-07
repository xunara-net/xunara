package state

import (
	"sync"
	"testing"

	"tailscale.com/types/key"
)

func TestMemoryStoreCreateAndGet(t *testing.T) {
	s := NewMemoryStore()

	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	n := Node{MachineKey: mk, NodeKey: nk, Hostname: "host1"}
	if err := s.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if n.ID == 0 {
		t.Error("expected an assigned ID")
	}
	if n.StableID == "" {
		t.Error("expected an assigned stable ID")
	}
	if !n.IPv4.IsValid() || !n.IPv6.IsValid() {
		t.Errorf("expected assigned addresses, got v4=%v v6=%v", n.IPv4, n.IPv6)
	}
	if n.Created.IsZero() {
		t.Error("expected a creation time")
	}

	got, ok := s.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node not found by node key")
	}
	if got.Hostname != "host1" {
		t.Errorf("Hostname = %q, want host1", got.Hostname)
	}
	if got.FQDN() != "host1." {
		t.Errorf("FQDN = %q, want host1.", got.FQDN())
	}

	if _, ok := s.GetNodeByID(n.ID); !ok {
		t.Error("node not found by ID")
	}
	if _, ok := s.GetNodeByStableID(n.StableID); !ok {
		t.Error("node not found by stable ID")
	}
	if byMachine := s.GetNodesByMachineKey(mk); len(byMachine) != 1 {
		t.Errorf("GetNodesByMachineKey len = %d, want 1", len(byMachine))
	}
	if all := s.ListNodes(); len(all) != 1 {
		t.Errorf("ListNodes len = %d, want 1", len(all))
	}
}

func TestMemoryStoreDuplicateNodeKey(t *testing.T) {
	s := NewMemoryStore()
	nk := key.NewNode().Public()

	if err := s.CreateNode(&Node{NodeKey: nk}); err != nil {
		t.Fatalf("first CreateNode: %v", err)
	}
	if err := s.CreateNode(&Node{NodeKey: nk}); err != ErrNodeKeyExists {
		t.Fatalf("second CreateNode err = %v, want ErrNodeKeyExists", err)
	}
}

func TestMemoryStoreDeleteClearsIndexes(t *testing.T) {
	s := NewMemoryStore()
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	n := Node{MachineKey: mk, NodeKey: nk, Hostname: "gone"}
	if err := s.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	if err := s.DeleteNode(n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	if _, ok := s.GetNodeByNodeKey(nk); ok {
		t.Error("node still found by node key after delete")
	}
	if _, ok := s.GetNodeByID(n.ID); ok {
		t.Error("node still found by ID after delete")
	}
	if _, ok := s.GetNodeByStableID(n.StableID); ok {
		t.Error("node still found by stable ID after delete")
	}
	if byMachine := s.GetNodesByMachineKey(mk); len(byMachine) != 0 {
		t.Errorf("GetNodesByMachineKey len = %d, want 0", len(byMachine))
	}
}

func TestMemoryStoreAssignsUniqueAddresses(t *testing.T) {
	s := NewMemoryStore()
	seen := make(map[any]bool)
	for i := range 8 {
		n := Node{NodeKey: key.NewNode().Public()}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode %d: %v", i, err)
		}
		if seen[n.IPv4] {
			t.Fatalf("duplicate IPv4 %v", n.IPv4)
		}
		seen[n.IPv4] = true
	}
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
