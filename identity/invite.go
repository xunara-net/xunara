package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// Registration invites are how a person who is not an administrator gets an
// account on a deployment without an external identity provider. They are the
// only self-service way in, so they are single use, expire, carry the role
// they grant, and are stored hashed: the plaintext token exists only in the
// link the inviter copied.

// InvitePrefix marks a registration invite token so it is recognisable in
// logs and support requests without being usable.
const InvitePrefix = "xunara_invite_"

// ErrInviteNotFound is returned for an unknown invite ID or token.
var ErrInviteNotFound = errors.New("identity: registration invite not found")

// ErrInviteUsed is returned when an invite has already been redeemed.
var ErrInviteUsed = errors.New("identity: registration invite already used")

// ErrInviteExpired is returned when an invite is past its expiry.
var ErrInviteExpired = errors.New("identity: registration invite expired")

// RegistrationInvite is one single-use invitation.
type RegistrationInvite struct {
	ID        string
	TokenHash string
	Role      Role
	Note      string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt is zero until the invite is redeemed.
	UsedAt time.Time
	UsedBy tailcfg.UserID
}

// Redeemed reports whether the invite has been used.
func (i RegistrationInvite) Redeemed() bool { return !i.UsedAt.IsZero() }

// Expired reports whether the invite is past its expiry at now.
func (i RegistrationInvite) Expired(now time.Time) bool {
	return !i.ExpiresAt.IsZero() && now.After(i.ExpiresAt)
}

// NewRegistrationInviteOptions describes an invite to create.
type NewRegistrationInviteOptions struct {
	Role      Role
	Note      string
	CreatedBy string
	TTL       time.Duration
}

// RegistrationInviteStore stores registration invites.
type RegistrationInviteStore interface {
	// CreateRegistrationInvite stores an invite and returns it together with
	// the plaintext token, which is shown exactly once.
	CreateRegistrationInvite(opts NewRegistrationInviteOptions) (RegistrationInvite, string, error)
	// GetRegistrationInvite returns an invite by ID.
	GetRegistrationInvite(id string) (RegistrationInvite, bool)
	// ListRegistrationInvites returns every invite, newest first.
	ListRegistrationInvites() []RegistrationInvite
	// RevokeRegistrationInvite deletes an unused invite. Redeemed invites
	// are kept as a record, so revoking one fails with ErrInviteUsed.
	RevokeRegistrationInvite(id string) error
	// FindRegistrationInvite returns the invite a token refers to without
	// consuming it, so a caller can read the role it grants before creating
	// the account. Invalid, used and expired invites are errors.
	FindRegistrationInvite(token string) (RegistrationInvite, error)
	// RedeemRegistrationInvite consumes an invite atomically: exactly one
	// caller can turn a given token into an account, even under concurrent
	// submissions.
	RedeemRegistrationInvite(token string, userID tailcfg.UserID, now time.Time) (RegistrationInvite, error)
}

// inviteRole returns the role an invite may grant: an invite never mints
// another owner by accident, because promoting a user is an explicit act.
func inviteRole(r Role) (Role, error) {
	switch r {
	case RoleMember, RoleAdmin:
		return r, nil
	case "":
		return RoleMember, nil
	default:
		return "", fmt.Errorf("identity: registration invite cannot grant role %q", string(r))
	}
}

// normalizeInviteToken trims the token a browser submitted so a pasted link
// with padding still resolves.
func normalizeInviteToken(token string) string {
	return strings.TrimSpace(token)
}
