package state

import "time"

// AllowRate implements [RateLimitStore].
func (s *MemoryStore) AllowRate(scope string, limit int, window time.Duration, now time.Time) (bool, time.Duration, error) {
	if err := validateRateArgs(scope, limit, window); err != nil {
		return false, 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, allowed, retryAfter := consumeRate(s.rateLimits[scope], limit, window, now.UTC())
	if allowed {
		s.rateLimits[scope] = bucket
	}
	return allowed, retryAfter, nil
}

// PruneRateLimits implements [RateLimitStore].
func (s *MemoryStore) PruneRateLimits(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for scope, bucket := range s.rateLimits {
		if bucket.windowStart.Before(before) {
			delete(s.rateLimits, scope)
			removed++
		}
	}
	return removed, nil
}
