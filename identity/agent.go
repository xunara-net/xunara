package identity

import (
	"errors"
	"time"
)

// AgentToken is the credential a Xunara Agent (the native client) presents to
// /api/agent/v1.
//
// It is part of machine identity, not service or human identity: it is bound
// to one node's machine key and node key, and every request that uses it must
// repeat both keys, which the control plane checks against the stored node
// (AGENTS.md section 11). It never authenticates a browser or a human.
type AgentToken struct {
	// ID is the public identifier used for revocation and audit.
	ID string
	// NodeID is the control-plane node the token belongs to.
	NodeID int64
	// MachineKey and NodeKey are the node identity the token is bound to,
	// stored as their canonical string form.
	MachineKey string
	NodeKey    string

	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// AgentTokenPrefix marks Xunara Agent tokens, so secret scanners can find
// them.
const AgentTokenPrefix = "xunara_agent_"

// ErrAgentTokenNotFound is returned for an unknown, expired or revoked agent
// token. The cases are indistinguishable to callers on purpose.
var ErrAgentTokenNotFound = errors.New("identity: agent token not found")

// NewAgentTokenOptions are the inputs to
// [AgentTokenStore.CreateAgentToken].
type NewAgentTokenOptions struct {
	NodeID     int64
	MachineKey string
	NodeKey    string
	// TTL bounds the token's lifetime. Zero means it never expires; enrolling
	// again rotates it.
	TTL time.Duration
}

// Live reports whether the token is usable at now.
func (t AgentToken) Live(now time.Time) bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	return t.ExpiresAt.IsZero() || now.Before(t.ExpiresAt)
}

// AgentTokenStore is the durable native-client credential table.
type AgentTokenStore interface {
	// CreateAgentToken creates a token and returns it. Only the token's hash
	// is stored, so the token is returned exactly once.
	CreateAgentToken(opts NewAgentTokenOptions) (AgentToken, string, error)

	// GetAgentTokenByToken resolves a token to a live credential. Unknown,
	// expired and revoked tokens all return ErrAgentTokenNotFound.
	GetAgentTokenByToken(token string) (AgentToken, error)

	// TouchAgentToken records the token's last use.
	TouchAgentToken(id string, now time.Time) error

	// RevokeAgentTokensForNode revokes every token bound to a node. Enrolling
	// again calls it before issuing a replacement, so a node holds at most one
	// live token.
	RevokeAgentTokensForNode(nodeID int64) error

	// ListAgentTokensForNode returns a node's tokens, newest first, including
	// revoked ones (for administration).
	ListAgentTokensForNode(nodeID int64) []AgentToken

	// ListAgentTokens returns tokens across every node, newest first, at most
	// limit of them (0 means no limit), including revoked ones.
	ListAgentTokens(limit int) []AgentToken

	// RevokeAgentToken revokes one token by public ID. Unknown and already
	// revoked tokens are a no-op; callers distinguish them by looking the
	// token up first when the difference matters.
	RevokeAgentToken(id string, now time.Time) error
}
