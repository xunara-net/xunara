package state

import (
	"sort"
	"time"
)

// validateReachSession checks the immutable shape of a new session. The
// control plane enforces the same limits at the API edge; the store refuses
// anything that slipped through so a bad row cannot exist.
func validateReachSession(session *ReachSession) error {
	if session.Sender == 0 || session.Target == 0 {
		return ErrReachSessionState
	}
	if session.Sender == session.Target {
		return ErrReachSessionState
	}
	if session.State != "" && session.State != ReachOffered {
		return ErrReachSessionState
	}
	if len(session.Argv) == 0 || len(session.Argv) > ReachMaxArgvEntries {
		return ErrReachSessionState
	}
	total := 0
	for _, arg := range session.Argv {
		if arg == "" || len(arg) > ReachMaxArgBytes {
			return ErrReachSessionState
		}
		total += len(arg)
	}
	if total > ReachMaxArgvBytes {
		return ErrReachSessionState
	}
	if session.Timeout <= 0 || session.Timeout > ReachMaxTimeout {
		return ErrReachSessionState
	}
	return nil
}

// validateReachChunk checks one output chunk's shape.
func validateReachChunk(stream string, seq int64, data []byte, maxTotal int64) error {
	if !ReachChunkStreamValid(stream) || seq < 0 || len(data) == 0 {
		return ErrReachSessionState
	}
	if len(data) > ReachMaxChunkBytes || maxTotal <= 0 {
		return ErrReachSessionState
	}
	return nil
}

// truncateReachError bounds the static error text.
func truncateReachError(text string) string {
	if len(text) <= ReachErrorLimit {
		return text
	}
	return text[:ReachErrorLimit]
}

// sortReachSessions orders sessions newest first, with the ID as a stable
// tiebreaker for sessions created in the same instant.
func sortReachSessions(sessions []ReachSession) {
	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].CreatedAt.Equal(sessions[j].CreatedAt) {
			return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
		}
		return sessions[i].ID < sessions[j].ID
	})
}

// copyReachSession returns a session the caller may mutate freely.
func copyReachSession(session ReachSession) ReachSession {
	session.Argv = append([]string(nil), session.Argv...)
	if session.ExitCode != nil {
		exitCode := *session.ExitCode
		session.ExitCode = &exitCode
	}
	return session
}

// ReachExpiry is the deadline a session carries while running: the command
// timeout plus a grace period for the target to report the result.
func ReachExpiry(now time.Time, timeout time.Duration) time.Time {
	return now.UTC().Add(timeout + ReachFinishGrace)
}
