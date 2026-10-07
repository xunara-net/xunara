package identity

import (
	"fmt"
	"strings"
)

// Role is a user's authority level in the tailnet.
//
// Roles gate the platform layer (console, /api/v1, CLI), never the client
// protocol: an official client's netmap and DERP access depend only on its
// registration state, not on who approved it (AGENTS.md section 12).
type Role string

const (
	// RoleMember may sign in and inspect the tailnet but not change it.
	RoleMember Role = "member"
	// RoleAdmin manages machines, routes, DNS, policy, pre-auth keys and
	// device approvals.
	RoleAdmin Role = "admin"
	// RoleOwner additionally manages users, roles and the users' service
	// identities (API keys and sessions). Every tailnet needs at least one.
	RoleOwner Role = "owner"
)

// ParseRole parses a role name, case-insensitively.
func ParseRole(s string) (Role, error) {
	switch r := Role(strings.ToLower(strings.TrimSpace(s))); r {
	case RoleMember, RoleAdmin, RoleOwner:
		return r, nil
	case "":
		return "", fmt.Errorf("identity: empty role")
	default:
		return "", fmt.Errorf("identity: unknown role %q", s)
	}
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleMember, RoleAdmin, RoleOwner:
		return true
	}
	return false
}

// CanWrite reports whether the role may change tailnet state (machines,
// routes, DNS, policy, pre-auth keys, device approvals).
func (r Role) CanWrite() bool {
	return r == RoleAdmin || r == RoleOwner
}

// IsOwner reports whether the role may manage users, roles and service
// identities.
func (r Role) IsOwner() bool { return r == RoleOwner }

// String implements fmt.Stringer.
func (r Role) String() string { return string(r) }
