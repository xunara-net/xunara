package control

import (
	"testing"

	"tailscale.com/tailcfg"
)

// TestGrantCapGrantReachesNetmap checks a grants app capability is delivered
// in the destination's packet filter.
func TestGrantCapGrantReachesNetmap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"grants": [{
				"src": ["*"],
				"dst": ["autogroup:self"],
				"app": {"example.com/cap/x": [{"scope": "read"}]},
			}],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "grant-a")
	defer connA.Close()
	connB, _, nodeKeyB := registerNode(t, s, hs, "grant-b")
	defer connB.Close()

	nodeA, ok := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	if !ok {
		t.Fatal("node A not found")
	}
	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node B not found")
	}

	resp := decodeMapResponse(t, postRaw(t, clientA, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
	}), "")
	rules := resp.PacketFilters["base"]
	if len(rules) != 1 || len(rules[0].CapGrant) != 1 {
		t.Fatalf("filter rules = %+v, want one cap grant rule", rules)
	}
	grant := rules[0].CapGrant[0]
	if len(grant.Dsts) == 0 || grant.Dsts[0].String() != nodeA.IPv4.String()+"/32" {
		t.Errorf("CapGrant.Dsts = %v, want this node's address", grant.Dsts)
	}
	if len(rules[0].SrcIPs) != 1 || rules[0].SrcIPs[0] != "*" {
		t.Errorf("SrcIPs = %v, want the wildcard source", rules[0].SrcIPs)
	}
	_ = nodeB
	values, ok := grant.CapMap[tailcfg.PeerCapability("example.com/cap/x")]
	if !ok || len(values) != 1 {
		t.Fatalf("CapMap = %+v, want the granted capability", grant.CapMap)
	}
	if string(values[0]) != `{"scope":"read"}` {
		t.Errorf("cap value = %s, want the document's JSON", values[0])
	}
}
