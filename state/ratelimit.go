package state

import (
	"fmt"
	"time"
)

// RateLimitStore is a durable fixed-window rate limiter.
//
// Buckets are named by an opaque scope string (for example
// "id-token:<node>:<audience>"). State is durable and shared through the
// store, not held in a server-local map, so every instance of a control
// plane sees the same counters across restarts (AGENTS.md section 9).
type RateLimitStore interface {
	// AllowRate consumes one unit from the bucket named scope. limit is the
	// maximum number of units per window and must be positive; window must be
	// positive. When the bucket is full it returns allowed=false with the time
	// remaining until the window ends.
	AllowRate(scope string, limit int, window time.Duration, now time.Time) (allowed bool, retryAfter time.Duration, err error)

	// PruneRateLimits removes buckets whose window started before the cutoff.
	// Buckets are not tied to a node, so they are reclaimed by age; the count
	// of removed buckets is returned.
	PruneRateLimits(before time.Time) (int, error)
}

// rateBucket is one fixed-window counter.
type rateBucket struct {
	windowStart time.Time
	count       int
}

// consumeRate applies the fixed-window rule to one bucket. It is the single
// definition of the semantics, shared by the memory and SQLite stores.
func consumeRate(bucket rateBucket, limit int, window time.Duration, now time.Time) (rateBucket, bool, time.Duration) {
	if bucket.windowStart.IsZero() || !now.Before(bucket.windowStart.Add(window)) {
		return rateBucket{windowStart: now, count: 1}, true, 0
	}
	if bucket.count >= limit {
		return bucket, false, bucket.windowStart.Add(window).Sub(now)
	}
	bucket.count++
	return bucket, true, 0
}

// validateRateArgs rejects configurations that could not be enforced.
func validateRateArgs(scope string, limit int, window time.Duration) error {
	if scope == "" {
		return fmt.Errorf("state: rate limit scope must not be empty")
	}
	if limit <= 0 {
		return fmt.Errorf("state: rate limit must be positive, got %d", limit)
	}
	if window <= 0 {
		return fmt.Errorf("state: rate limit window must be positive, got %v", window)
	}
	return nil
}
