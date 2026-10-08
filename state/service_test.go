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
			{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"},
				Visibility: []string{"group:eng", "tag:prod"}},
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
		if !slices.Equal(all[0].Visibility, []string{"group:eng", "tag:prod"}) {
			t.Errorf("api visibility = %v, want group:eng then tag:prod", all[0].Visibility)
		}
		if all[1].Visibility != nil {
			t.Errorf("metrics visibility = %v, want nil (default discovery)", all[1].Visibility)
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

	t.Run("health reporting", func(t *testing.T) {
		s := newStore(t)
		node := createTestNode(t, s, "health")
		if err := s.ReplaceNodeServices(node.ID, []Service{
			{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
			{Name: "web", Protocol: "tcp", Port: 80},
		}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}

		// Tracked but never reported: not discoverable (fail-closed), and the
		// untracked service is untouched.
		got := serviceByName(t, s, "api")
		if !got.Health || got.Healthy || !got.HealthReportedAt.IsZero() {
			t.Fatalf("unreported tracked service = %+v", got)
		}
		if got.EffectiveHealth() != ServiceHealthUnhealthy {
			t.Errorf("EffectiveHealth = %q, want unhealthy", got.EffectiveHealth())
		}
		if web := serviceByName(t, s, "web"); web.Health || web.EffectiveHealth() != ServiceHealthUntracked {
			t.Errorf("untracked service = %+v", web)
		}

		// First ready report is a transition; repeating it is not.
		changes, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "api", Ready: true}}, time.Minute)
		if err != nil {
			t.Fatalf("ReportServiceHealth: %v", err)
		}
		if len(changes) != 1 || changes[0].Name != "api" || !changes[0].Healthy || changes[0].Reason != ServiceHealthReasonReported {
			t.Fatalf("changes = %+v", changes)
		}
		got = serviceByName(t, s, "api")
		if !got.Healthy || got.EffectiveHealth() != ServiceHealthHealthy {
			t.Fatalf("reported service = %+v", got)
		}
		if got.HealthReportedAt.IsZero() || !got.HealthUntil.After(got.HealthReportedAt) {
			t.Errorf("report timestamps = %+v", got)
		}
		if again, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "api", Ready: true}}, time.Minute); err != nil {
			t.Fatalf("ReportServiceHealth again: %v", err)
		} else if len(again) != 0 {
			t.Errorf("repeated report produced changes: %+v", again)
		}

		// A complete report omits "api": it becomes not ready.
		changes, err = s.ReportServiceHealth(node.ID, nil, time.Minute)
		if err != nil {
			t.Fatalf("ReportServiceHealth (empty): %v", err)
		}
		if len(changes) != 1 || changes[0].Healthy {
			t.Fatalf("changes after an empty report = %+v", changes)
		}
		if got = serviceByName(t, s, "api"); got.Healthy {
			t.Errorf("service stayed healthy after being left out of a report")
		}

		// Reports must name a tracked service.
		if _, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "web", Ready: true}}, time.Minute); !errors.Is(err, ErrServiceHealthUnknown) {
			t.Errorf("reporting an untracked service = %v, want ErrServiceHealthUnknown", err)
		}
		if _, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "missing", Ready: true}}, time.Minute); !errors.Is(err, ErrServiceHealthUnknown) {
			t.Errorf("reporting an unknown service = %v, want ErrServiceHealthUnknown", err)
		}
		if _, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "api", Ready: true}, {Name: "api", Ready: false}}, time.Minute); err == nil {
			t.Error("duplicate report entries were accepted")
		}
		if _, err := s.ReportServiceHealth(node.ID, nil, 0); err == nil {
			t.Error("a non-positive TTL was accepted")
		}
		if _, err := s.ReportServiceHealth(node.ID+1000, nil, time.Minute); err == nil {
			t.Error("reporting for an unknown node succeeded")
		}
	})

	t.Run("health survives republish and expires", func(t *testing.T) {
		s := newStore(t)
		node := createTestNode(t, s, "health")
		if err := s.ReplaceNodeServices(node.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080, Health: true}}); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}
		if _, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "api", Ready: true}}, time.Minute); err != nil {
			t.Fatalf("ReportServiceHealth: %v", err)
		}

		// A periodic republish of the same declaration keeps the report.
		if err := s.ReplaceNodeServices(node.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080, Health: true}}); err != nil {
			t.Fatalf("republish: %v", err)
		}
		if got := serviceByName(t, s, "api"); !got.Healthy {
			t.Fatalf("republish dropped the standing report: %+v", got)
		}

		// Turning tracking off clears the health state; turning it back on
		// starts from not ready.
		if err := s.ReplaceNodeServices(node.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080}}); err != nil {
			t.Fatalf("republish without health: %v", err)
		}
		if got := serviceByName(t, s, "api"); got.Health || got.Healthy || !got.HealthReportedAt.IsZero() {
			t.Fatalf("health state after disabling tracking = %+v", got)
		}
		if err := s.ReplaceNodeServices(node.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080, Health: true}}); err != nil {
			t.Fatalf("republish with health again: %v", err)
		}
		if got := serviceByName(t, s, "api"); got.Healthy || got.HealthReportedAt.IsZero() == false {
			t.Fatalf("re-enabled tracking kept a stale report: %+v", got)
		}

		// Expiry withdraws the service; a second sweep is a no-op.
		if _, err := s.ReportServiceHealth(node.ID, []ServiceHealthReport{{Name: "api", Ready: true}}, time.Minute); err != nil {
			t.Fatalf("ReportServiceHealth: %v", err)
		}
		changes, err := s.ExpireServiceHealth(time.Now().UTC().Add(2 * time.Minute))
		if err != nil {
			t.Fatalf("ExpireServiceHealth: %v", err)
		}
		if len(changes) != 1 || changes[0].Name != "api" || changes[0].Healthy || changes[0].Reason != ServiceHealthReasonExpired {
			t.Fatalf("expired changes = %+v", changes)
		}
		if got := serviceByName(t, s, "api"); got.Healthy || got.EffectiveHealth() != ServiceHealthUnhealthy {
			t.Errorf("service after expiry = %+v", got)
		}
		if again, err := s.ExpireServiceHealth(time.Now().UTC().Add(2 * time.Minute)); err != nil || len(again) != 0 {
			t.Errorf("second expiry sweep = %+v, %v", again, err)
		}
	})
}

// serviceByName fetches a service the test just published.
func serviceByName(t *testing.T, s Store, name string) Service {
	t.Helper()
	svc, ok := s.GetServiceByName(name)
	if !ok {
		t.Fatalf("GetServiceByName(%q) = not found", name)
	}
	return svc
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
	got.Visibility = append(got.Visibility, "*")
	again := s.ListServices()[0]
	if again.Metadata["version"] != "1" {
		t.Errorf("metadata after tampering = %q, want 1", again.Metadata["version"])
	}
	if len(again.Visibility) != 0 {
		t.Errorf("visibility after tampering = %v, want the stored (empty) value", again.Visibility)
	}

	if !slices.Equal([]string{again.Name}, []string{"api"}) {
		t.Errorf("unexpected service set: %+v", again)
	}
}
