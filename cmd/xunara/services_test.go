package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"tailscale.com/types/key"

	"github.com/xunara/xunara/state"
)

// seedServiceStore builds an in-memory store with two nodes, one advertising
// two services.
func seedServiceStore(t *testing.T) (state.Store, state.Node) {
	t.Helper()

	store := state.NewMemoryStore()
	web := state.Node{Hostname: "web", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&web); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	quiet := state.Node{Hostname: "quiet", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&quiet); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	if err := store.ReplaceNodeServices(web.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		{Name: "metrics", Protocol: "tcp", Port: 9090},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	return store, web
}

// TestWriteServicesList covers the list view: every service with its
// publisher.
func TestWriteServicesList(t *testing.T) {
	store, web := seedServiceStore(t)

	var buf bytes.Buffer
	if err := writeServicesList(&buf, store); err != nil {
		t.Fatalf("writeServicesList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"api", "metrics", "tcp", "8080", "9090", "web", web.StableID} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "quiet") {
		t.Errorf("list shows a node without services:\n%s", out)
	}

	var empty bytes.Buffer
	if err := writeServicesList(&empty, state.NewMemoryStore()); err != nil {
		t.Fatalf("writeServicesList (empty): %v", err)
	}
	if !strings.Contains(empty.String(), "No services have been advertised") {
		t.Errorf("empty list output = %q", empty.String())
	}
}

// TestWriteServicesShow covers the detail view, metadata and the unknown-name
// error.
func TestWriteServicesShow(t *testing.T) {
	store, web := seedServiceStore(t)

	var buf bytes.Buffer
	if err := writeServicesShow(&buf, store, "api"); err != nil {
		t.Fatalf("writeServicesShow: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"api", "tcp", "8080", "web", web.StableID, "version", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("show output lacks %q:\n%s", want, out)
		}
	}

	if err := writeServicesShow(&bytes.Buffer{}, store, "nope"); !errors.Is(err, errServiceNotFound) {
		t.Errorf("unknown service error = %v, want errServiceNotFound", err)
	}
}
