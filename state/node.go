// Package state holds Xunara's tailnet state model: the nodes registered on a
// tailnet and the operations the control plane performs on them.
//
// The package deliberately exposes a small [Store] interface so that the
// Compatibility Core (control/) depends on an interface rather than a concrete
// database, keeping the dependency direction Platform -> Core interfaces
// (AGENTS.md section 13).
package state

import (
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// NodeID is the server-local, stable identifier of a node. It is distinct from
// the wire [tailcfg.NodeID] only in package ownership; the numeric value is
// what is sent to clients.
type NodeID uint64

// RegisterMethod records how a node's identity became authorized.
//
// Human and machine identity stay separate (AGENTS.md section 5): an
// interactive login authorizes a *machine*, it never turns a NodeKey into a
// human user.
type RegisterMethod string

const (
	// RegisterMethodAuthKey is a node authorized by a pre-authentication key.
	RegisterMethodAuthKey RegisterMethod = "auth_key"
	// RegisterMethodInteractive is a node authorized through the browser login
	// flow (OIDC/OAuth/WebAuthn/... at a later milestone).
	RegisterMethodInteractive RegisterMethod = "interactive"
)

// Node is a registered machine on a tailnet.
//
// A Node is a value type so that reads from the [Store] never hand out a
// pointer that could be mutated concurrently.
type Node struct {
	ID       NodeID
	StableID string

	// MachineKey is the machine's long-lived Noise key, bound at the TS2021
	// handshake. It is one half of machine identity.
	MachineKey key.MachinePublic
	// NodeKey is the node's WireGuard key, derived from the machine's tailscale
	// state. It is one half of node identity.
	NodeKey key.NodePublic
	// DiscoKey is the node's magicsock discovery key.
	DiscoKey key.DiscoPublic

	// UserID is the owning user. In the single-tenant milestone this is always
	// [DefaultUserID].
	UserID tailcfg.UserID

	// Hostname is the machine's self-reported hostname.
	Hostname string

	// IPv4 and IPv6 are the tailnet addresses assigned to this node.
	IPv4 netip.Addr
	IPv6 netip.Addr

	// Endpoints are the node's most recently reported magicsock endpoints, as
	// carried in MapRequest.Endpoints.
	Endpoints []netip.AddrPort

	// HomeDERP is the DERP region the node is homed to, if known.
	HomeDERP tailcfg.DERPRegionID

	// CapVer is the capability version the node last advertised. It is
	// advertised to peers so they can gate behaviour per node.
	CapVer tailcfg.CapabilityVersion

	// Hostinfo is the most recent host info seen for the node. It is treated as
	// immutable after it is set; callers must not mutate it in place.
	Hostinfo *tailcfg.Hostinfo

	// LastSeen is when the node's last control session ended. It is nil for a
	// node that has never completed a session.
	LastSeen *time.Time

	// Expiry is when the node key expires. The zero value means the key never
	// expires.
	Expiry time.Time
	// RequestedExpiry is the expiry the client asked for, before server policy
	// is applied. It is not persisted.
	RequestedExpiry time.Time `json:"-"`
	// Created is when the node was created.
	Created time.Time
	// Method records how the node was authorized.
	Method RegisterMethod

	// Ephemeral marks nodes that should be reaped once inactive.
	Ephemeral bool
}

// DefaultUserID is the user every node is attributed to until multi-user
// identity lands.
const DefaultUserID tailcfg.UserID = 1

// Identity attribute values for [DefaultUserID]. They are the single source of
// truth for how the local user is described to clients.
const (
	// DefaultLoginName is the login name reported for the local user.
	DefaultLoginName = "local"
	// DefaultDisplayName is the display name reported for the local user.
	DefaultDisplayName = "Xunara User"
	// DefaultProvider is the identity provider name reported for the local user.
	DefaultProvider = "xunara"
)

// DefaultUserProfile builds the wire profile for a user in the single-user
// milestone.
func DefaultUserProfile(id tailcfg.UserID) tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:          id,
		LoginName:   DefaultLoginName,
		DisplayName: DefaultDisplayName,
	}
}

// DefaultUser builds the wire user for a user in the single-user milestone.
func DefaultUser(id tailcfg.UserID, created time.Time) tailcfg.User {
	return tailcfg.User{
		ID:          id,
		DisplayName: DefaultDisplayName,
		Created:     created,
	}
}

// Expired reports whether the node's key expiry has passed. The zero expiry is
// never expired.
func (n Node) Expired(now time.Time) bool {
	return !n.Expiry.IsZero() && n.Expiry.Before(now)
}

// FQDN returns the node's fully-qualified MagicDNS name, always with a
// trailing dot.
func (n Node) FQDN() string {
	name := n.Hostname
	if name == "" {
		name = fmt.Sprintf("node-%d", n.ID)
	}
	return name + "."
}
