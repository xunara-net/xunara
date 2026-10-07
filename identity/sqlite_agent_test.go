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
