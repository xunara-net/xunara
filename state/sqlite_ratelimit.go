package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AllowRate implements [RateLimitStore].
func (s *SQLiteStore) AllowRate(scope string, limit int, window time.Duration, now time.Time) (bool, time.Duration, error) {
	if err := validateRateArgs(scope, limit, window); err != nil {
		return false, 0, err
	}
	now = now.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
	}
	defer tx.Rollback()

	var (
		startNanos int64
		count      int
	)
	err = tx.QueryRowContext(ctx, "SELECT window_start, count FROM rate_limits WHERE scope = ?", scope).
		Scan(&startNanos, &count)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rate_limits(scope, window_start, count) VALUES(?, ?, 1)",
			scope, now.UnixNano()); err != nil {
			return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
		}
		if err := tx.Commit(); err != nil {
			return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
		}
		return true, 0, nil
	case err != nil:
		return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
	}

	bucket, allowed, retryAfter := consumeRate(rateBucket{
		windowStart: time.Unix(0, startNanos).UTC(),
		count:       count,
	}, limit, window, now)
	if allowed {
		if _, err := tx.ExecContext(ctx,
			"UPDATE rate_limits SET window_start = ?, count = ? WHERE scope = ?",
			bucket.windowStart.UnixNano(), bucket.count, scope); err != nil {
			return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("state: rate limiting %q: %w", scope, err)
	}
	return allowed, retryAfter, nil
}

// PruneRateLimits implements [RateLimitStore].
func (s *SQLiteStore) PruneRateLimits(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM rate_limits WHERE window_start < ?", before.UTC().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("state: pruning rate limits: %w", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("state: pruning rate limits: %w", err)
	}
	return int(removed), nil
}
