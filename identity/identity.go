// Package identity holds Xunara's trust plane: who a human, a machine and a
// service are, and how that came to be known.
//
// The package is built around three deliberately separate objects
// (AGENTS.md section 10):
//
//	AuthTransaction     one login attempt, with its OAuth state and PKCE
//	Session             a logged-in browser, revocable and expiring
//	DeviceAuthorization one machine waiting for a human to authorize it
//
// They share nothing but identifiers. A design that folds them into one cache
// entry is exactly what this package exists to avoid.
package identity

import (
	"time"

	"tailscale.com/tailcfg"
)

// User is a human (or service) identity in Xunara.
type User struct {
	ID          tailcfg.UserID
	LoginName   string
	DisplayName string
	// Email is an attribute, never an identity key (AGENTS.md section 6).
	Email string
	// Role gates the platform layer (console, API, CLI). The zero value is
	// treated as [RoleMember] on write and reported as-is on read.
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ExternalIdentity binds a user to an account at an external provider.
//
// The identity key is exactly (ProviderID, Subject). Email is stored for
// display and for matching heuristics an administrator may confirm, but it
// never identifies an account on its own.
type ExternalIdentity struct {
	ProviderID  string
	Subject     string
	UserID      tailcfg.UserID
	Email       string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IdentityResult is what a provider returns after a successful authentication.
//
// It is deliberately not a session: the caller decides which user to attach the
// result to, and creating a session is a separate, audited step.
type IdentityResult struct {
	// ProviderID identifies the provider that authenticated the subject.
	ProviderID string

	// Subject is the provider's stable, unique identifier for the account. It
	// is the only part of the result that is an identity key.
	Subject string

	// Email is an attribute the provider reports. It is never used to link
	// accounts automatically.
	Email string

	// DisplayName is a human-readable name, for display only.
	DisplayName string

	// Claims are the raw claims, for claims mapping and debugging. They must
	// not be logged verbatim: they can contain tokens.
	Claims map[string]any
}

// LocalProviderID is the provider ID used for locally created users.
const LocalProviderID = "local"

// LocalLoginName is the login name of the single-user tailnet's user.
const LocalLoginName = "local"

// LocalDisplayName is the display name of that user.
const LocalDisplayName = "Xunara User"

// EnsureLocalUser creates the built-in local user when the store is empty.
//
// It returns the user and whether it was created. The first user gets ID 1,
// which is the ID nodes and pre-auth keys default to.
func EnsureLocalUser(store Store) (User, bool, error) {
	if users := store.ListUsers(); len(users) > 0 {
		return users[0], false, nil
	}

	u := User{
		LoginName:   LocalLoginName,
		DisplayName: LocalDisplayName,
		// The built-in user bootstraps the tailnet and owns it: someone must
		// be able to grant the first OIDC user a role.
		Role: RoleOwner,
	}
	if err := store.CreateUser(&u); err != nil {
		return User{}, false, err
	}

	// The local user is also reachable as an external identity, so a
	// deployment that later adds an OIDC provider keeps a stable key for it.
	ei := ExternalIdentity{
		ProviderID:  LocalProviderID,
		Subject:     LocalLoginName,
		UserID:      u.ID,
		DisplayName: u.DisplayName,
	}
	if err := store.LinkExternalIdentity(&ei); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// AuditEvent is one entry in the control plane's audit log.
//
// The actor is recorded as a free-form string ("user:1", "system", "cli") so
// that machine, human and service actors stay distinguishable in the log.
type AuditEvent struct {
	ID     uint64
	Time   time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

// AuditActions are the actions this build records. They are constants so that
// the log stays greppable and so that action names cannot drift.
const (
	AuditUserCreated     = "user.created"
	AuditUserUpdated     = "user.updated"
	AuditUserRoleChanged = "user.role_changed"
	AuditNodeRegistered  = "node.registered"
	AuditNodeApproved    = "node.approved"
	AuditNodeReaped      = "node.reaped"
	AuditNodeDeleted     = "node.deleted"
	// AuditNodeDisconnectReported is a client-reported disconnect (the user
	// ran `tailscale down` or the node shut down), delivered through
	// /machine/audit-log.
	AuditNodeDisconnectReported = "node.disconnect_reported"
	// AuditAgentEnrolled records a native client (Xunara Agent) enrolling or
	// rotating its machine-bound credential.
	AuditAgentEnrolled     = "agent.enrolled"
	AuditRouteApproved     = "route.approved"
	AuditRouteUnapproved   = "route.unapproved"
	AuditDNSRecordSet      = "dns.record_set"
	AuditDNSRecordDeleted  = "dns.record_deleted"
	AuditPolicyReloaded    = "policy.reloaded"
	AuditPreAuthKeyCreated = "preauthkey.created"
	AuditPreAuthKeyDeleted = "preauthkey.deleted"
	AuditLoginSucceeded    = "login.succeeded"
	AuditLoginFailed       = "login.failed"
	AuditSessionCreated    = "session.created"
	AuditSessionRevoked    = "session.revoked"
	AuditDeviceApproved    = "device.approved"
	AuditDeviceDenied      = "device.denied"
	AuditTagRejected       = "device.tag_rejected"
	AuditAPIKeyCreated     = "apikey.created"
	AuditAPIKeyRevoked     = "apikey.revoked"
	AuditSSHCheckApproved  = "ssh.check_approved"
	AuditSSHCheckDenied    = "ssh.check_denied"
)
