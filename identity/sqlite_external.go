package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const externalIdentityColumns = "provider_id, subject, user_id, email, display_name, created_at, updated_at"

// LinkExternalIdentity implements [ExternalIdentityStore].
func (s *SQLiteStore) LinkExternalIdentity(ei *ExternalIdentity) error {
	if ei == nil || ei.ProviderID == "" || ei.Subject == "" {
		return fmt.Errorf("identity: external identity needs a provider and a subject")
	}

	now := time.Now().UTC()
	if ei.CreatedAt.IsZero() {
		ei.CreatedAt = now
	}
	ei.UpdatedAt = now

	// (provider, subject) is the identity key: linking an account that is
	// already attached to another user must fail rather than silently move it.
	var existingUser int64
	err := s.db.QueryRowContext(context.Background(),
		"SELECT user_id FROM external_identities WHERE provider_id = ? AND subject = ?",
		ei.ProviderID, ei.Subject).Scan(&existingUser)
	switch {
	case err == nil && tailcfg.UserID(existingUser) != ei.UserID:
		return ErrExternalIdentityExists
	case err == nil:
		_, err = s.db.ExecContext(context.Background(),
			`UPDATE external_identities SET email = ?, display_name = ?, updated_at = ?
			 WHERE provider_id = ? AND subject = ?`,
			ei.Email, ei.DisplayName, ei.UpdatedAt.UnixNano(), ei.ProviderID, ei.Subject)
		if err != nil {
			return fmt.Errorf("identity: updating external identity: %w", err)
		}
		return nil
	case err != sql.ErrNoRows:
		return fmt.Errorf("identity: looking up external identity: %w", err)
	}

	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO external_identities (`+externalIdentityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ei.ProviderID, ei.Subject, int64(ei.UserID), ei.Email, ei.DisplayName,
		ei.CreatedAt.UnixNano(), ei.UpdatedAt.UnixNano())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrExternalIdentityExists
		}
		return fmt.Errorf("identity: linking external identity: %w", err)
	}
	return nil
}

// GetExternalIdentity implements [ExternalIdentityStore].
func (s *SQLiteStore) GetExternalIdentity(provider, subject string) (ExternalIdentity, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+externalIdentityColumns+" FROM external_identities WHERE provider_id = ? AND subject = ?",
		provider, subject)

	ei, err := scanExternalIdentity(row)
	if err != nil {
		return ExternalIdentity{}, false
	}
	return ei, true
}

// ListExternalIdentities implements [ExternalIdentityStore].
func (s *SQLiteStore) ListExternalIdentities(userID tailcfg.UserID) []ExternalIdentity {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+externalIdentityColumns+" FROM external_identities WHERE user_id = ? ORDER BY provider_id, subject",
		int64(userID))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []ExternalIdentity
	for rows.Next() {
		ei, err := scanExternalIdentity(rows)
		if err != nil {
			return nil
		}
		out = append(out, ei)
	}
	return out
}

// UnlinkExternalIdentity implements [ExternalIdentityStore].
func (s *SQLiteStore) UnlinkExternalIdentity(provider, subject string) error {
	_, err := s.db.ExecContext(context.Background(),
		"DELETE FROM external_identities WHERE provider_id = ? AND subject = ?", provider, subject)
	if err != nil {
		return fmt.Errorf("identity: unlinking external identity: %w", err)
	}
	return nil
}

func scanExternalIdentity(sc scanner) (ExternalIdentity, error) {
	var (
		provider  string
		subject   string
		userID    int64
		email     string
		display   string
		createdAt int64
		updatedAt int64
	)
	if err := sc.Scan(&provider, &subject, &userID, &email, &display, &createdAt, &updatedAt); err != nil {
		return ExternalIdentity{}, err
	}
	return ExternalIdentity{
		ProviderID:  provider,
		Subject:     subject,
		UserID:      tailcfg.UserID(userID),
		Email:       email,
		DisplayName: display,
		CreatedAt:   time.Unix(0, createdAt).UTC(),
		UpdatedAt:   time.Unix(0, updatedAt).UTC(),
	}, nil
}
