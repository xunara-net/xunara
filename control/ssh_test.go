package control

import (
	"slices"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

// TestSSHPolicyReachesNodes checks the compiled Tailscale SSH policy and the
// cap/ssh capability arrive in the netmap when the tailnet's policy has an
// "ssh" section.
func TestSSHPolicyReachesNodes(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"ssh": [{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self"],
				"users": ["autogroup:nonroot", "root"],
			}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "ssh-a")
	defer connA.Close()
	connB, _, nodeKeyB := registerNode(t, s, hs, "ssh-b")
	defer connB.Close()

	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node b not found")
	}

	resp := decodeMapResponse(t, postRaw(t, clientA, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
	}), "")

	if resp.SSHPolicy == nil || len(resp.SSHPolicy.Rules) == 0 {
		t.Fatalf("SSHPolicy = %+v, want at least one rule", resp.SSHPolicy)
	}
	var principals []string
	for _, rule := range resp.SSHPolicy.Rules {
		for _, p := range rule.Principals {
			principals = append(principals, p.NodeIP)
		}
		if rule.Action == nil || !rule.Action.Accept {
			t.Errorf("action = %+v, want accept", rule.Action)
		}
	}
	if !slices.Contains(principals, nodeB.IPv4.String()) {
		t.Errorf("principals = %v, want the peer address %s", principals, nodeB.IPv4)
	}

	// The destination capability lets a client run its SSH server.
	if _, ok := resp.Node.CapMap[tailcfg.CapabilitySSH]; !ok {
		t.Errorf("self CapMap = %v, want %s", resp.Node.CapMap, tailcfg.CapabilitySSH)
	}
	var peerSeen bool
	for _, peer := range resp.Peers {
		if strings.HasPrefix(peer.Name, "ssh-b.") {
			peerSeen = true
			if _, ok := peer.CapMap[tailcfg.CapabilitySSH]; !ok {
				t.Errorf("peer CapMap = %v, want %s", peer.CapMap, tailcfg.CapabilitySSH)
			}
		}
	}
	if !peerSeen {
		t.Fatalf("peer ssh-b missing from netmap: %+v", resp.Peers)
	}
}

// TestNoSSHSectionMeansNoPolicy keeps the default netmap free of SSH state.
func TestNoSSHSectionMeansNoPolicy(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "plain")
	defer conn.Close()

	resp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	if resp.SSHPolicy != nil {
		t.Errorf("SSHPolicy = %+v, want nil", resp.SSHPolicy)
	}
	if _, ok := resp.Node.CapMap[tailcfg.CapabilitySSH]; ok {
		t.Error("a tailnet without ssh rules must not advertise cap/ssh")
	}
}
