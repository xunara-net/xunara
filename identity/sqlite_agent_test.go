package identity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestAgentTokenLifecycle covers the native-client credential: issuance,
// binding, rotation and revocation.
func TestAgentTokenLifecycle(t *testing.T) {
	s := openTestStore(t)

	token, secret, err := s.CreateAgentToken(NewAgentTokenOptions{
		NodeID:     7,
		MachineKey: "mkey:abc",
		NodeKey:    "nodekey:def",
	})
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if token.ID == "" || secret == "" {
		t.Fatal("CreateAgentToken returned an empty credential")
	}
	if !strings.HasPrefix(secret, AgentTokenPrefix) {
		t.Errorf("token %q lacks the %q prefix", secret, AgentTokenPrefix)
	}

	got, err := s.GetAgentTokenByToken(secret)
	if err != nil {
		t.Fatalf("GetAgentTokenByToken: %v", err)
	}
	if got.NodeID != 7 || got.MachineKey != "mkey:abc" || got.NodeKey != "nodekey:def" {
		t.Errorf("resolved token = %+v, want the bound node identity", got)
	}

	if _, err := s.GetAgentTokenByToken(""); !errors.Is(err, ErrAgentTokenNotFound) {
		t.Errorf("empty token error = %v, want ErrAgentTokenNotFound", err)
	}
	if _, err := s.GetAgentTokenByToken("xunara_agent_nope"); !errors.Is(err, ErrAgentTokenNotFound) {
		t.Errorf("unknown token error = %v, want ErrAgentTokenNotFound", err)
	}

	// Re-enrolling rotates: old tokens are revoked and a fresh one is issued.
	if err := s.RevokeAgentTokensForNode(7); err != nil {
		t.Fatalf("RevokeAgentTokensForNode: %v", err)
	}
	if _, err := s.GetAgentTokenByToken(secret); !errors.Is(err, ErrAgentTokenNotFound) {
		t.Errorf("revoked token error = %v, want ErrAgentTokenNotFound", err)
	}

	_, second, err := s.CreateAgentToken(NewAgentTokenOptions{
		NodeID:     7,
		MachineKey: "mkey:abc",
		NodeKey:    "nodekey:def",
	})
	if err != nil {
		t.Fatalf("second CreateAgentToken: %v", err)
	}
	if second == secret {
		t.Error("rotation reused the old token")
	}
	if _, err := s.GetAgentTokenByToken(second); err != nil {
		t.Errorf("rotated token does not resolve: %v", err)
	}

	tokens := s.ListAgentTokensForNode(7)
	if len(tokens) != 2 {
		t.Fatalf("tokens = %d, want 2 (one revoked, one live)", len(tokens))
	}
	if tokens[0].CreatedAt.Before(tokens[1].CreatedAt) {
		t.Error("ListAgentTokensForNode is not newest-first")
	}
	if err := s.TouchAgentToken(tokens[0].ID, time.Now().UTC()); err != nil {
		t.Fatalf("TouchAgentToken: %v", err)
	}
}

// TestAgentTokenListAllAndRevokeOne covers the administration surface: listing
// across nodes and revoking a single credential.
func TestAgentTokenListAllAndRevokeOne(t *testing.T) {
	s := openTestStore(t)

	for _, node := range []int64{1, 2, 3} {
		if _, _, err := s.CreateAgentToken(NewAgentTokenOptions{
			NodeID:     node,
			MachineKey: "mkey",
			NodeKey:    "nodekey",
		}); err != nil {
			t.Fatalf("CreateAgentToken(%d): %v", node, err)
		}
	}

	all := s.ListAgentTokens(0)
	if len(all) != 3 {
		t.Fatalf("ListAgentTokens = %d, want 3", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt.After(all[i-1].CreatedAt) {
			t.Fatal("ListAgentTokens is not newest-first")
		}
	}
	if limited := s.ListAgentTokens(2); len(limited) != 2 {
		t.Errorf("ListAgentTokens(2) = %d, want 2", len(limited))
	}

	if err := s.RevokeAgentToken(all[0].ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}
	// Idempotent, and an unknown or empty ID is a no-op.
	if err := s.RevokeAgentToken(all[0].ID, time.Now().UTC()); err != nil {
		t.Fatalf("repeated RevokeAgentToken: %v", err)
	}
	if err := s.RevokeAgentToken("", time.Now().UTC()); err != nil {
		t.Fatalf("empty RevokeAgentToken: %v", err)
	}
	if err := s.RevokeAgentToken("missing", time.Now().UTC()); err != nil {
		t.Fatalf("unknown RevokeAgentToken: %v", err)
	}

	revoked := s.ListAgentTokensForNode(all[0].NodeID)
	if len(revoked) != 1 || revoked[0].RevokedAt.IsZero() {
		t.Errorf("token not revoked: %+v", revoked)
	}
	live := s.ListAgentTokensForNode(all[1].NodeID)
	if len(live) != 1 || !live[0].RevokedAt.IsZero() {
		t.Errorf("other node's token was revoked: %+v", live)
	}
}

// TestAgentTokenExpiry checks that an expired credential stops resolving.
func TestAgentTokenExpiry(t *testing.T) {
	s := openTestStore(t)

	_, secret, err := s.CreateAgentToken(NewAgentTokenOptions{
		NodeID:     1,
		MachineKey: "mkey:a",
		NodeKey:    "nodekey:b",
		TTL:        time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	if _, err := s.GetAgentTokenByToken(secret); !errors.Is(err, ErrAgentTokenNotFound) {
		t.Errorf("expired token error = %v, want ErrAgentTokenNotFound", err)
	}

	// Invalid inputs are refused at creation.
	if _, _, err := s.CreateAgentToken(NewAgentTokenOptions{NodeID: 0, MachineKey: "m", NodeKey: "n"}); err == nil {
		t.Error("token without a node ID was accepted")
	}
	if _, _, err := s.CreateAgentToken(NewAgentTokenOptions{NodeID: 1, MachineKey: "", NodeKey: ""}); err == nil {
		t.Error("token without keys was accepted")
	}
}
