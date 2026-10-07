package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// streamStallTimeout is how long the client tolerates silence on the event
// stream before it treats the server as gone. The server sends a keepalive
// comment well inside this window.
const streamStallTimeout = 2 * time.Minute

// maxEventBytes caps one SSE line. A netmap frame is a single (long) data
// line, so this must fit the largest legitimate netmap.
const maxEventBytes = 64 << 20

// StreamNetmap opens the server's event stream and calls onChange with every
// netmap frame until ctx is cancelled, the stream ends, or the server stalls.
//
// The stream is the push half of the protocol: while it is open there is no
// need to poll. Callers should treat an error the same way as a failed
// poll and reconnect with backoff; [IsStreamUnsupported] tells an older
// server's "no such endpoint" apart from a real failure.
func (c *Client) StreamNetmap(ctx context.Context, token string, keys Keys, onChange func(*tailcfg.MapResponse) error) error {
	if c.BaseURL == "" {
		return errors.New("agent protocol: no server URL")
	}
	if onChange == nil {
		return errors.New("agent protocol: event stream needs a handler")
	}

	// A stream is long-lived by design, so the request timeout that bounds
	// ordinary calls must not apply.
	streamClient := &http.Client{}
	if c.HTTP != nil {
		client := *c.HTTP
		client.Timeout = 0
		streamClient = &client
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/agent/v1/events", nil)
	if err != nil {
		return fmt.Errorf("agent protocol: building event stream request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "xunara-agent")
	req.Header.Set("Authorization", "Bearer "+token)
	// A GET carries no body, so the keys the credential is bound to travel as
	// headers. They are public keys, never secrets.
	req.Header.Set("X-Xunara-Machine-Key", keys.Machine.Public().String())
	req.Header.Set("X-Xunara-Node-Key", keys.Node.Public().String())

	resp, err := streamClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent protocol: event stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(msg)),
		}
	}

	return consumeEvents(ctx, resp.Body, onChange)
}

// consumeEvents parses an SSE body and dispatches netmap events.
func consumeEvents(ctx context.Context, body io.Reader, onChange func(*tailcfg.MapResponse) error) error {
	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 64<<10), maxEventBytes)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		readErr <- scanner.Err()
	}()

	stall := time.NewTimer(streamStallTimeout)
	defer stall.Stop()

	var (
		event string
		data  []string
	)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stall.C:
			return errors.New("agent protocol: event stream stalled")
		case err := <-readErr:
			if err == nil {
				return io.EOF
			}
			return fmt.Errorf("agent protocol: reading event stream: %w", err)
		case line := <-lines:
			resetTimer(stall, streamStallTimeout)

			switch {
			case line == "":
				if err := dispatchEvent(event, data, onChange); err != nil {
					return err
				}
				event, data = "", nil
			case strings.HasPrefix(line, ":"):
				// Keepalive comment.
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				value := strings.TrimPrefix(line, "data:")
				value = strings.TrimPrefix(value, " ")
				data = append(data, value)
			default:
				// "retry:" and unknown fields do not affect the agent; the
				// daemon owns its own backoff.
			}
		}
	}
}

// dispatchEvent handles one complete SSE event.
func dispatchEvent(event string, data []string, onChange func(*tailcfg.MapResponse) error) error {
	if len(data) == 0 {
		return nil
	}
	switch event {
	case "netmap":
		var netmap tailcfg.MapResponse
		if err := json.Unmarshal([]byte(strings.Join(data, "\n")), &netmap); err != nil {
			return fmt.Errorf("agent protocol: decoding netmap event: %w", err)
		}
		return onChange(&netmap)
	default:
		// Unknown event types are ignored: the server may add events a newer
		// client understands, and an older client must not break on them.
		return nil
	}
}

// resetTimer restarts t, draining a pending fire first.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// IsStreamUnsupported reports whether err means this server does not have the
// event stream endpoint (an older control plane). The agent then keeps
// polling instead of treating it as a failure.
func IsStreamUnsupported(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	switch he.StatusCode {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}
