package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const inviteColumns = "id, token_hash, role, note, created_by, created_at, expires_at, used_at, used_by"

// CreateRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) CreateRegistrationInvite(opts NewRegistrationInviteOptions) (RegistrationInvite, string, error) {
	role, err := inviteRole(opts.Role)
	if err != nil {
		return RegistrationInvite{}, "", err
	}

	secret, err := newSecret()
	if err != nil {
		return RegistrationInvite{}, "", err
	}
	token := InvitePrefix + secret

	id, err := newID("inv-")
	if err != nil {
		return RegistrationInvite{}, "", err
	}

	now := time.Now().UTC()
	invite := RegistrationInvite{
		ID:        id,
		TokenHash: HashSecret(token),
		Role:      role,
		Note:      opts.Note,
		CreatedBy: opts.CreatedBy,
		CreatedAt: now,
	}
	if opts.TTL > 0 {
		invite.ExpiresAt = now.Add(opts.TTL)
	}

	// expires_at uses the package's zero sentinel for "no expiry" rather
	// than the zero time's UnixNano, which is a date in 1754 and would make
	// every invite without a TTL look long expired.
	if _, err := s.db.ExecContext(context.Background(),
		"INSERT INTO registration_invites ("+inviteColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
		invite.ID, invite.TokenHash, string(invite.Role), invite.Note, invite.CreatedBy,
		invite.CreatedAt.UnixNano(), timeToNanos(invite.ExpiresAt)); err != nil {
		return RegistrationInvite{}, "", fmt.Errorf("identity: creating registration invite: %w", err)
	}
	return invite, token, nil
}

// GetRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) GetRegistrationInvite(id string) (RegistrationInvite, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+inviteColumns+" FROM registration_invites WHERE id = ?", id)
	invite, err := scanInvite(row)
	if err != nil {
		return RegistrationInvite{}, false
	}
	return invite, true
}

// ListRegistrationInvites implements [RegistrationInviteStore].
func (s *SQLiteStore) ListRegistrationInvites() []RegistrationInvite {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+inviteColumns+" FROM registration_invites ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []RegistrationInvite
	for rows.Next() {
		invite, err := scanInvite(rows)
		if err != nil {
			return nil
		}
		out = append(out, invite)
	}
	return out
}

// RevokeRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) RevokeRegistrationInvite(id string) error {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM registration_invites WHERE id = ? AND used_at IS NULL", id)
	if err != nil {
		return fmt.Errorf("identity: revoking registration invite: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: revoking registration invite: %w", err)
	}
	if affected == 0 {
		// Either the invite does not exist or it was already redeemed; the
		// second case is reported separately so the console can explain it.
		if invite, ok := s.GetRegistrationInvite(id); ok && invite.Redeemed() {
			return ErrInviteUsed
		}
		return ErrInviteNotFound
	}
	return nil
}

// FindRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) FindRegistrationInvite(token string) (RegistrationInvite, error) {
	token = normalizeInviteToken(token)
	if token == "" {
		return RegistrationInvite{}, ErrInviteNotFound
	}
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+inviteColumns+" FROM registration_invites WHERE token_hash = ?", HashSecret(token))
	invite, err := scanInvite(row)
	if err != nil {
		return RegistrationInvite{}, ErrInviteNotFound
	}
	switch {
	case invite.Redeemed():
		return RegistrationInvite{}, ErrInviteUsed
	case invite.Expired(time.Now().UTC()):
		return RegistrationInvite{}, ErrInviteExpired
	}
	return invite, nil
}

// RedeemRegistrationInvite implements [RegistrationInviteStore].
//
// The UPDATE ... WHERE used_at IS NULL is the whole concurrency control: two
// browsers submitting the same invite race on the row and exactly one wins,
// which is why redemption does not read the row first and write it later.
func (s *SQLiteStore) RedeemRegistrationInvite(token string, userID tailcfg.UserID, now time.Time) (RegistrationInvite, error) {
	token = normalizeInviteToken(token)
	if token == "" {
		return RegistrationInvite{}, ErrInviteNotFound
	}

	ctx := context.Background()
	hash := HashSecret(token)

	row := s.db.QueryRowContext(ctx, "SELECT "+inviteColumns+" FROM registration_invites WHERE token_hash = ?", hash)
	invite, err := scanInvite(row)
	if err != nil {
		return RegistrationInvite{}, ErrInviteNotFound
	}
	switch {
	case invite.Redeemed():
		return RegistrationInvite{}, ErrInviteUsed
	case invite.Expired(now):
		return RegistrationInvite{}, ErrInviteExpired
	}

	res, err := s.db.ExecContext(ctx,
		"UPDATE registration_invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL",
		now.UnixNano(), int64(userID), invite.ID)
	if err != nil {
		return RegistrationInvite{}, fmt.Errorf("identity: redeeming registration invite: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return RegistrationInvite{}, fmt.Errorf("identity: redeeming registration invite: %w", err)
	}
	if affected == 0 {
		return RegistrationInvite{}, ErrInviteUsed
	}
	invite.UsedAt = now
	invite.UsedBy = userID
	return invite, nil
}

func scanInvite(sc scanner) (RegistrationInvite, error) {
	var (
		id        string
		tokenHash string
		role      string
		note      string
		createdBy string
		createdAt int64
		expiresAt sql.NullInt64
		usedAt    sql.NullInt64
		usedBy    sql.NullInt64
	)
	if err := sc.Scan(&id, &tokenHash, &role, &note, &createdBy, &createdAt, &expiresAt, &usedAt, &usedBy); err != nil {
		return RegistrationInvite{}, err
	}
	invite := RegistrationInvite{
		ID:        id,
		TokenHash: tokenHash,
		Role:      Role(role),
		Note:      note,
		CreatedBy: createdBy,
		CreatedAt: time.Unix(0, createdAt).UTC(),
	}
	if expiresAt.Valid {
		invite.ExpiresAt = nanosToTime(expiresAt.Int64)
	}
	if usedAt.Valid {
		invite.UsedAt = time.Unix(0, usedAt.Int64).UTC()
	}
	if usedBy.Valid {
		invite.UsedBy = tailcfg.UserID(usedBy.Int64)
	}
	return invite, nil
}
