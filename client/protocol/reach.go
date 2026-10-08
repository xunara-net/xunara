package protocol

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// This file is the native client's half of Xunara Reach remote command
// execution (PROJECT_SPEC section 29). Sessions are orchestrated by the
// control plane; the command runs on the target agent, which the operator has
// to approve first.

// Client-side mirrors of the control plane's reach limits (state.Reach*,
// PROJECT_SPEC section 29.2). The server re-checks all of them; these exist so
// the CLI and the agent can refuse a bad command without a round trip.
const (
	// ReachMaxArgvEntries, ReachMaxArgvBytes and ReachMaxArgBytes bound argv.
	ReachMaxArgvEntries = 16
	ReachMaxArgvBytes   = 16 << 10
	ReachMaxArgBytes    = 4 << 10
	// ReachMaxTimeout is the longest command timeout a session may carry.
	ReachMaxTimeout = 15 * time.Minute
	// ReachMaxChunkBytes is one output chunk and ReachMaxOutputBytes the
	// total output of one session, both before base64.
	ReachMaxChunkBytes  = 24 << 10
	ReachMaxOutputBytes = 2 << 20
	// ReachMaxChunksPerRead bounds one chunk read.
	ReachMaxChunksPerRead = 64
)

// Reach session states, matching the control plane's vocabulary.
const (
	ReachOffered   = "offered"
	ReachAccepted  = "accepted"
	ReachRunning   = "running"
	ReachSucceeded = "succeeded"
	ReachFailed    = "failed"
	ReachDenied    = "denied"
	ReachCanceled  = "canceled"
	ReachExpired   = "expired"
)

// ReachStdout and ReachStderr name the output streams.
const (
	ReachStdout = "stdout"
	ReachStderr = "stderr"
)

// ReachPeer is one participant as the control plane reports it.
type ReachPeer struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname,omitempty"`
}

// ReachSession is one remote command session.
type ReachSession struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	Sender     ReachPeer `json:"sender"`
	Target     ReachPeer `json:"target"`
	Argv       []string  `json:"argv"`
	TimeoutSec int       `json:"timeoutSec"`
	ExitCode   *int      `json:"exitCode,omitempty"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Terminal reports whether the session will not change state again.
func (s ReachSession) Terminal() bool {
	switch s.State {
	case ReachSucceeded, ReachFailed, ReachDenied, ReachCanceled, ReachExpired:
		return true
	default:
		return false
	}
}

// ReachChunk is one piece of command output.
type ReachChunk struct {
	Stream    string    `json:"stream"`
	Seq       int64     `json:"seq"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"createdAt"`
}

// ReachChunks is one output read: chunks per stream plus the cursors to pass
// next time.
type ReachChunks struct {
	Out     []ReachChunk `json:"out"`
	Err     []ReachChunk `json:"err"`
	NextOut int64        `json:"nextOut"`
	NextErr int64        `json:"nextErr"`
}

// ReachOffer asks a target to run a command (POST /reach/sessions). Only the
// target's approval lets it run; this call just asks.
func (c *Client) ReachOffer(ctx context.Context, token string, keys Keys, to string, argv []string, timeout time.Duration) (ReachSession, error) {
	body := struct {
		To         string   `json:"to"`
		Argv       []string `json:"argv"`
		TimeoutSec int      `json:"timeoutSec,omitempty"`
	}{To: to, Argv: argv, TimeoutSec: int(timeout / time.Second)}

	var resp struct {
		Session ReachSession `json:"session"`
	}
	if err := c.doFluxJSON(ctx, http.MethodPost, "/api/agent/v1/reach/sessions", token, keys, body, &resp); err != nil {
		return ReachSession{}, err
	}
	return resp.Session, nil
}

// ReachList lists every session this node takes part in (GET /reach/sessions).
func (c *Client) ReachList(ctx context.Context, token string, keys Keys) ([]ReachSession, error) {
	var resp struct {
		Sessions []ReachSession `json:"sessions"`
	}
	if err := c.doFluxJSON(ctx, http.MethodGet, "/api/agent/v1/reach/sessions", token, keys, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

// ReachGet fetches one session (GET /reach/sessions/{id}).
func (c *Client) ReachGet(ctx context.Context, token string, keys Keys, id string) (ReachSession, error) {
	var resp struct {
		Session ReachSession `json:"session"`
	}
	if err := c.doFluxJSON(ctx, http.MethodGet, reachPath(id), token, keys, nil, &resp); err != nil {
		return ReachSession{}, err
	}
	return resp.Session, nil
}

// ReachAccept approves an offer (POST /reach/sessions/{id}/accept). Only the
// target can accept.
func (c *Client) ReachAccept(ctx context.Context, token string, keys Keys, id string) (ReachSession, error) {
	return c.reachDecision(ctx, token, keys, reachPath(id, "accept"), nil)
}

// ReachDeny refuses an offer (POST /reach/sessions/{id}/deny).
func (c *Client) ReachDeny(ctx context.Context, token string, keys Keys, id string) (ReachSession, error) {
	return c.reachDecision(ctx, token, keys, reachPath(id, "deny"), nil)
}

// ReachStart marks an accepted session as running (POST .../start). Only the
// target's execution loop calls this.
func (c *Client) ReachStart(ctx context.Context, token string, keys Keys, id string) (ReachSession, error) {
	return c.reachDecision(ctx, token, keys, reachPath(id, "start"), nil)
}

// ReachCancel withdraws a session; either participant may do so.
func (c *Client) ReachCancel(ctx context.Context, token string, keys Keys, id string) (ReachSession, error) {
	return c.reachDecision(ctx, token, keys, reachPath(id, "cancel"), nil)
}

// ReachFinish reports the command result (POST .../finish). Only the target
// calls this after the process ended.
func (c *Client) ReachFinish(ctx context.Context, token string, keys Keys, id string, exitCode int, errText string) (ReachSession, error) {
	body := struct {
		ExitCode int    `json:"exitCode"`
		Error    string `json:"error,omitempty"`
	}{ExitCode: exitCode, Error: errText}
	return c.reachDecision(ctx, token, keys, reachPath(id, "finish"), body)
}

// reachDecision posts a state transition and decodes the session.
func (c *Client) reachDecision(ctx context.Context, token string, keys Keys, path string, body any) (ReachSession, error) {
	var resp struct {
		Session ReachSession `json:"session"`
	}
	if err := c.doFluxJSON(ctx, http.MethodPost, path, token, keys, body, &resp); err != nil {
		return ReachSession{}, err
	}
	return resp.Session, nil
}

// ReachAppendChunk stores one output chunk (POST .../chunks). The target
// sends sequential chunks per stream; a retried sequence is rejected by the
// control plane rather than duplicating output.
func (c *Client) ReachAppendChunk(ctx context.Context, token string, keys Keys, id, stream string, seq int64, data []byte) error {
	body := struct {
		Stream string `json:"stream"`
		Seq    int64  `json:"seq"`
		Data   []byte `json:"data"`
	}{Stream: stream, Seq: seq, Data: data}
	return c.doFluxJSON(ctx, http.MethodPost, reachPath(id, "chunks"), token, keys, body, nil)
}

// ReachChunks reads output after the given per-stream cursors (GET
// .../chunks?out=&err=).
func (c *Client) ReachChunks(ctx context.Context, token string, keys Keys, id string, afterOut, afterErr int64) (ReachChunks, error) {
	query := url.Values{}
	if afterOut >= 0 {
		query.Set("out", strconv.FormatInt(afterOut, 10))
	}
	if afterErr >= 0 {
		query.Set("err", strconv.FormatInt(afterErr, 10))
	}
	path := reachPath(id, "chunks")
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}

	var chunks ReachChunks
	if err := c.doFluxJSON(ctx, http.MethodGet, path, token, keys, nil, &chunks); err != nil {
		return ReachChunks{}, err
	}
	return chunks, nil
}

// reachPath builds a reach endpoint path.
func reachPath(id string, parts ...string) string {
	path := "/api/agent/v1/reach/sessions/" + url.PathEscape(id)
	for _, part := range parts {
		path += "/" + url.PathEscape(part)
	}
	return path
}
