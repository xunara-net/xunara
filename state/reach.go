package state

// This file holds the control plane's bookkeeping for Xunara Reach remote
// command execution (PROJECT_SPEC section 29). The control plane orchestrates
// sessions and relays output chunks; it never runs a command itself.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ReachState is where a remote command session is in its lifecycle.
type ReachState string

const (
	// ReachOffered: the sender offered a command, the target has not answered.
	ReachOffered ReachState = "offered"
	// ReachAccepted: the target approved; its agent may start the command.
	ReachAccepted ReachState = "accepted"
	// ReachRunning: the command is executing on the target.
	ReachRunning ReachState = "running"
	// ReachSucceeded: the command exited with status 0.
	ReachSucceeded ReachState = "succeeded"
	// ReachFailed: the command exited non-zero, could not start, timed out or
	// exceeded the output limit.
	ReachFailed ReachState = "failed"
	// ReachDenied: the target refused the offer.
	ReachDenied ReachState = "denied"
	// ReachCanceled: either side withdrew the session.
	ReachCanceled ReachState = "canceled"
	// ReachExpired: the session passed its deadline unanswered or with the
	// target gone.
	ReachExpired ReachState = "expired"
)

// Active reports whether the session still waits for an action or holds
// resources. Terminal sessions are kept briefly so both sides can read the
// outcome, then pruned.
func (s ReachState) Active() bool {
	switch s {
	case ReachOffered, ReachAccepted, ReachRunning:
		return true
	default:
		return false
	}
}

// Valid reports whether the state is one this build knows.
func (s ReachState) Valid() bool {
	switch s {
	case ReachOffered, ReachAccepted, ReachRunning, ReachSucceeded,
		ReachFailed, ReachDenied, ReachCanceled, ReachExpired:
		return true
	default:
		return false
	}
}

// Reach limits. They are shared by the control plane (enforcement) and the
// CLI (early validation) so neither side can disagree about what is allowed.
const (
	// ReachMaxArgvEntries and ReachMaxArgvBytes bound the command.
	ReachMaxArgvEntries = 16
	ReachMaxArgvBytes   = 16 << 10
	// ReachMaxArgBytes bounds a single argv entry.
	ReachMaxArgBytes = 4 << 10
	// ReachMaxTimeout is the longest a session may run.
	ReachMaxTimeout = 15 * time.Minute

	// ReachMaxChunkBytes is one output chunk (before base64).
	ReachMaxChunkBytes = 24 << 10
	// ReachMaxOutputBytes is the total output a session may produce.
	ReachMaxOutputBytes = 2 << 20
	// ReachMaxChunksPerRead bounds one chunk read.
	ReachMaxChunksPerRead = 64
	// ReachMaxActivePerPair bounds concurrent sessions between two nodes.
	ReachMaxActivePerPair = 8
	// ReachMaxOfferAge is how long an unanswered offer waits.
	ReachMaxOfferAge = 5 * time.Minute
	// ReachFinishGrace is how long after its timeout the target may still
	// report the result before the janitor expires a running session.
	ReachFinishGrace = 30 * time.Second
)

// ReachErrorLimit bounds the static error text stored with a failed session.
const ReachErrorLimit = 300

// ReachStreams are the output streams a session may carry. Interactive stdin
// is deliberately absent: v1 has no PTY and no stdin (spec 29).
const (
	ReachStreamStdout = "stdout"
	ReachStreamStderr = "stderr"
)

// ReachChunkStreamValid reports whether stream is a stream this build accepts.
func ReachChunkStreamValid(stream string) bool {
	return stream == ReachStreamStdout || stream == ReachStreamStderr
}

// ReachSession is one remote command session.
type ReachSession struct {
	ID     string
	Sender NodeID
	Target NodeID
	State  ReachState
	// Argv is the command, executed element by element without a shell.
	Argv []string
	// Timeout is how long the command may run once started.
	Timeout time.Duration
	// ExitCode is set once the command finished (pointer because 0 is valid).
	ExitCode *int
	// Error is a short static explanation of a failure; empty otherwise.
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
	// ExpiresAt bounds the current phase: the offer age before accept, the
	// execution window while running.
	ExpiresAt time.Time
}

// ReachChunk is one piece of command output.
type ReachChunk struct {
	Stream    string
	Seq       int64
	Data      []byte
	CreatedAt time.Time
}

// ReachQuotas bounds session creation.
type ReachQuotas struct {
	// MaxActivePerPair bounds concurrent non-terminal sessions between the
	// same sender and target. Zero means [ReachMaxActivePerPair].
	MaxActivePerPair int
}

func (q ReachQuotas) maxActivePerPair() int {
	if q.MaxActivePerPair > 0 {
		return q.MaxActivePerPair
	}
	return ReachMaxActivePerPair
}

// Reach errors; control maps them onto HTTP statuses.
var (
	// ErrReachSessionNotFound is returned when a session does not exist.
	ErrReachSessionNotFound = errors.New("state: reach session not found")
	// ErrReachSessionState is returned when a session exists but is not in a
	// state that allows the requested transition.
	ErrReachSessionState = errors.New("state: reach session is not in a state that allows this")
	// ErrReachSessionQuota is returned when a pair has too many active
	// sessions.
	ErrReachSessionQuota = errors.New("state: reach session quota exceeded")
	// ErrReachChunkDuplicate is returned when a chunk sequence already exists;
	// it prevents a retry from duplicating output.
	ErrReachChunkDuplicate = errors.New("state: reach chunk already stored")
	// ErrReachOutputLimit is returned when a chunk would exceed the session
	// output cap; the target must stop the command and finish the session.
	ErrReachOutputLimit = errors.New("state: reach output limit exceeded")
)

// NewReachSessionID returns a random session identifier.
func NewReachSessionID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("state: generating a reach session ID: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// ReachStore is the persistence boundary for remote command sessions.
type ReachStore interface {
	// CreateReachSession assigns an ID (when empty) and stores a new offered
	// session. It fails with [ErrReachSessionQuota] when the pair already has
	// the maximum number of active sessions.
	CreateReachSession(s *ReachSession, quotas ReachQuotas) error
	// GetReachSession returns a session by ID.
	GetReachSession(id string) (ReachSession, bool)
	// ListReachSessions returns every session the node participates in
	// (sender or target), newest first.
	ListReachSessions(nodeID NodeID) []ReachSession
	// ListAllReachSessions returns every session, newest first. It backs the
	// read-only management surface (spec section 31), which sees both sides
	// of every session of this organization.
	ListAllReachSessions() []ReachSession
	// ReachOutputBytes returns how many bytes of output one session holds per
	// stream. An unknown session reports zeros; callers check existence
	// through GetReachSession.
	ReachOutputBytes(id string) (stdout, stderr int64, err error)
	// SetReachSessionState performs a compare-and-set transition. It returns
	// false when the session is not in the from state.
	SetReachSessionState(id string, from, to ReachState, now time.Time) (bool, error)
	// StartReachSession runs the accepted -> running transition and extends
	// the deadline to the execution window.
	StartReachSession(id string, expiresAt, now time.Time) (bool, error)
	// FinishReachSession records the terminal result of a running session
	// (succeeded on exit code 0, failed otherwise).
	FinishReachSession(id string, exitCode int, errText string, now time.Time) (bool, error)
	// AppendReachChunk stores one output chunk. maxTotal caps the total bytes
	// across all chunks of the session ([ErrReachOutputLimit] beyond it).
	AppendReachChunk(id, stream string, seq int64, data []byte, maxTotal int64, now time.Time) error
	// ReachChunks returns the chunks of one stream after a sequence number.
	ReachChunks(id, stream string, after int64, limit int) ([]ReachChunk, error)
	// ExpireReachSessions moves active sessions past their deadline to
	// expired and returns them (for auditing).
	ExpireReachSessions(now time.Time) ([]ReachSession, error)
	// DeleteReachSessions removes terminal sessions last updated before the
	// cutoff and returns how many went.
	DeleteReachSessions(before time.Time) (int, error)
}
