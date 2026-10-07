package state

import (
	"errors"
	"slices"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// runServiceConformance exercises the [ServiceStore] contract. Both
// implementations must pass it.
func runServiceConformance(t *testing.T, newStore storeFactory) {
	t.Run("publish and read back", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		if err := s.ReplaceNodeServices(first.ID, []Service{
			{Name: "metrics", Protocol: "tcp", Port: 9090},
			{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}

		all := s.ListServices()
		if len(all) != 2 || all[0].Name != "api" || all[1].Name != "metrics" {
			t.Fatalf("ListServices = %+v, want api then metrics", all)
		}
		if all[0].NodeID != first.ID || all[0].Protocol != "tcp" || all[0].Port != 8080 {
			t.Errorf("api service = %+v", all[0])
		}
		if all[0].Metadata["version"] != "2" || all[0].Created.IsZero() || all[0].Updated.IsZero() {
			t.Errorf("api metadata/timestamps = %+v", all[0])
		}
		if all[1].Metadata != nil {
			t.Errorf("metrics metadata = %v, want nil", all[1].Metadata)
		}
		if got, err := s.ServicesForNode(first.ID); err != nil || len(got) != 2 {
			t.Errorf("ServicesForNode(first) = %+v, %v", got, err)
		}
		if got, err := s.ServicesForNode(second.ID); err != nil || len(got) != 0 {
			t.Errorf("ServicesForNode(second) = %+v, %v, want none", got, err)
		}
		if svc, ok := s.GetServiceByName("api"); !ok || svc.Port != 8080 {
			t.Errorf("GetServiceByName(api) = %+v, %v", svc, ok)
		}
		if _, ok := s.GetServiceByName("nope"); ok {
			t.Error("GetServiceByName found an unknown name")
		}
		counts, err := s.NodeServiceCounts()
		if err != nil {
			t.Fatalf("NodeServiceCounts: %v", err)
		}
		if counts[first.ID] != 2 || counts[second.ID] != 0 {
			t.Errorf("counts = %+v", counts)
		}
	})

	t.Run("replace is declarative and keeps creation times", func(t *testing.T) {
		s := newStore(t)
		node := createTestNode(t, s, "node")

		if err := s.ReplaceNodeServices(node.ID, []Service{
			{Name: "api", Protocol: "tcp", Port: 8080},
			{Name: "old", Protocol: "udp", Port: 5000},
		}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}
		created := s.ListServices()[0].Created

		time.Sleep(2 * time.Millisecond)
		if err := s.ReplaceNodeServices(node.ID, []Service{
			{Name: "api", Protocol: "tcp", Port: 8081},
		}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}

		got := s.ListServices()
		if len(got) != 1 || got[0].Name != "api" || got[0].Port != 8081 {
			t.Fatalf("services after replace = %+v", got)
		}
		if !got[0].Created.Equal(created) {
			t.Errorf("created = %v, want the original %v", got[0].Created, created)
		}
		if got[0].Updated.Before(got[0].Created) {
			t.Errorf("updated = %v, before created %v", got[0].Updated, got[0].Created)
		}

		// An empty replacement clears the node's set.
		if err := s.ReplaceNodeServices(node.ID, nil); err != nil {
			t.Fatalf("clearing: %v", err)
		}
		if got := s.ListServices(); len(got) != 0 {
			t.Errorf("services after clearing = %+v", got)
		}
	})

	t.Run("name conflicts fail without touching either node", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		if err := s.ReplaceNodeServices(first.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080}}); err != nil {
			t.Fatalf("ReplaceNodeServices(first): %v", err)
		}
		err := s.ReplaceNodeServices(second.ID, []Service{
			{Name: "other", Protocol: "tcp", Port: 1},
			{Name: "api", Protocol: "tcp", Port: 9999},
		})
		if !errors.Is(err, ErrServiceNameTaken) {
			t.Fatalf("conflicting replace error = %v, want ErrServiceNameTaken", err)
		}
		if _, ok := s.GetServiceByName("other"); ok {
			t.Error("a failed replace left a partial set behind")
		}
		if svc, _ := s.GetServiceByName("api"); svc.NodeID != first.ID || svc.Port != 8080 {
			t.Errorf("the original owner lost its name: %+v", svc)
		}

		// Duplicate names inside one request are refused too.
		err = s.ReplaceNodeServices(second.ID, []Service{
			{Name: "dup", Protocol: "tcp", Port: 1},
			{Name: "dup", Protocol: "udp", Port: 2},
		})
		if !errors.Is(err, ErrServiceNameTaken) {
			t.Errorf("duplicate-name error = %v, want ErrServiceNameTaken", err)
		}
	})

	t.Run("unknown node fails", func(t *testing.T) {
		s := newStore(t)
		if err := s.ReplaceNodeServices(NodeID(9999), []Service{{Name: "api", Protocol: "tcp", Port: 1}}); err == nil {
			t.Fatal("publishing for an unknown node succeeded")
		}
	})

	t.Run("deleting a node drops its services and frees its names", func(t *testing.T) {
		s := newStore(t)
		first := createTestNode(t, s, "first")
		second := createTestNode(t, s, "second")

		if err := s.ReplaceNodeServices(first.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080}}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}
		if err := s.DeleteNode(first.ID); err != nil {
			t.Fatalf("DeleteNode: %v", err)
		}
		if got := s.ListServices(); len(got) != 0 {
			t.Errorf("services after deleting the node = %+v", got)
		}
		if err := s.ReplaceNodeServices(second.ID, []Service{{Name: "api", Protocol: "tcp", Port: 1}}); err != nil {
			t.Errorf("the freed name could not be reused: %v", err)
		}
	})
}

// createTestNode creates a minimal node for service tests.
func createTestNode(t *testing.T, s Store, hostname string) Node {
	t.Helper()
	node := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: hostname}
	if err := s.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return node
}

func TestMemoryServiceConformance(t *testing.T) {
	runServiceConformance(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestSQLiteServiceConformance(t *testing.T) {
	runServiceConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, t.TempDir()+"/state.db")
	})
}

// TestServiceCopyIsolation checks that a returned service shares no state with
// the store: callers must not be able to mutate what a node published.
func TestServiceCopyIsolation(t *testing.T) {
	s := NewMemoryStore()
	node := createTestNode(t, s, "node")
	if err := s.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}

	got := s.ListServices()[0]
	got.Metadata["version"] = "tampered"
	again := s.ListServices()[0]
	if again.Metadata["version"] != "1" {
		t.Errorf("metadata after tampering = %q, want 1", again.Metadata["version"])
	}

	if !slices.Equal([]string{again.Name}, []string{"api"}) {
		t.Errorf("unexpected service set: %+v", again)
	}
}
