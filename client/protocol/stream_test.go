package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestStreamNetmapParsesEvents checks the SSE client: headers carry the
// credential and keys, keepalives and unknown events are ignored, and a netmap
// event is decoded.
func TestStreamNetmapParsesEvents(t *testing.T) {
	keys := Keys{Machine: key.NewMachine(), Node: key.NewNode()}
	want := tailcfg.MapResponse{
		Node:  &tailcfg.Node{ID: 7, Name: "agent.example.com."},
		Peers: []*tailcfg.Node{{ID: 8}, {ID: 9}},
	}

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/events" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("X-Xunara-Machine-Key"); got != keys.Machine.Public().String() {
			http.Error(w, "bad machine key", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("X-Xunara-Node-Key"); got != keys.Node.Public().String() {
			http.Error(w, "bad node key", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			http.Error(w, "bad accept", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		io.WriteString(w, "retry: 3000\n\n")
		io.WriteString(w, ": keepalive\n\n")
		payload, _ := json.Marshal(want)
		fmt.Fprintf(w, "event: netmap\ndata: %s\n\n", payload)
		flusher.Flush()
		// An unknown event must be ignored, not an error.
		io.WriteString(w, "event: future\ndata: {\"x\":1}\n\n")
		flusher.Flush()
	}))
	t.Cleanup(hs.Close)

	client := New(hs.URL)
	var got []*tailcfg.MapResponse
	err := client.StreamNetmap(context.Background(), "tok", keys, func(m *tailcfg.MapResponse) error {
		got = append(got, m)
		return nil
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("StreamNetmap error = %v, want io.EOF at end of stream", err)
	}
	if len(got) != 1 {
		t.Fatalf("netmaps = %d, want 1", len(got))
	}
	if got[0].Node == nil || got[0].Node.ID != 7 || len(got[0].Peers) != 2 {
		t.Errorf("netmap = %+v, want the server's frame", got[0])
	}
}

// TestStreamNetmapCancellation checks that cancelling the context ends the
// stream even when the server keeps it open forever.
func TestStreamNetmapCancellation(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		flusher.Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(hs.Close)

	keys := Keys{Machine: key.NewMachine(), Node: key.NewNode()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- New(hs.URL).StreamNetmap(ctx, "tok", keys, func(*tailcfg.MapResponse) error { return nil })
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("StreamNetmap error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StreamNetmap did not stop on cancellation")
	}
}

// TestStreamUnsupportedDetection checks the fallback signal for servers
// without the stream endpoint.
func TestStreamUnsupportedDetection(t *testing.T) {
	hs := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(hs.Close)

	keys := Keys{Machine: key.NewMachine(), Node: key.NewNode()}
	err := New(hs.URL).StreamNetmap(context.Background(), "tok", keys, func(*tailcfg.MapResponse) error { return nil })
	if err == nil {
		t.Fatal("StreamNetmap against a server without the endpoint succeeded")
	}
	if !IsStreamUnsupported(err) {
		t.Errorf("IsStreamUnsupported(%v) = false, want true", err)
	}

	if IsStreamUnsupported(&HTTPError{StatusCode: http.StatusUnauthorized}) {
		t.Error("401 reported as a missing endpoint")
	}
	if IsStreamUnsupported(errors.New("network down")) {
		t.Error("network error reported as a missing endpoint")
	}
}
