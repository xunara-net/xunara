package mapper

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/state"
)

func testNode(id state.NodeID, hostname string) state.Node {
	return state.Node{
		ID:         id,
		StableID:   fmt.Sprintf("n%d", id),
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     state.DefaultUserID,
		Hostname:   hostname,
		IPv4:       netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id)),
		IPv6:       netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%d", id)),
		Created:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CapVer:     tailcfg.CurrentCapabilityVersion,
	}
}

func neverOnline(state.NodeID) bool { return false }

func TestFullIncludesSelfPeersAndPolicy(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	resp := Full(self, []state.Node{peer, self}, Config{Domain: "xunara.test"}, neverOnline, tailcfg.CurrentCapabilityVersion)

	if resp.Node == nil || resp.Node.ID != tailcfg.NodeID(self.ID) {
		t.Fatalf("self node = %+v, want id %d", resp.Node, self.ID)
	}
	if resp.Node.Name != "self." {
		t.Errorf("self name = %q, want self.", resp.Node.Name)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("peers = %d, want 1 (self must be filtered out)", len(resp.Peers))
	}
	if resp.Peers[0].ID != tailcfg.NodeID(peer.ID) {
		t.Errorf("peer id = %d, want %d", resp.Peers[0].ID, peer.ID)
	}
	if len(resp.Peers[0].Addresses) != 2 {
		t.Errorf("peer addresses = %v, want 2 entries", resp.Peers[0].Addresses)
	}

	if resp.Domain != "xunara.test" {
		t.Errorf("domain = %q, want xunara.test", resp.Domain)
	}
	if resp.DNSConfig == nil || len(resp.DNSConfig.Domains) != 1 || !resp.DNSConfig.Proxied {
		t.Errorf("dns config = %+v, want proxied MagicDNS for the domain", resp.DNSConfig)
	}
	if _, ok := resp.PacketFilters["base"]; !ok {
		t.Error("missing base packet filter")
	}
	if len(resp.UserProfiles) != 1 {
		t.Errorf("user profiles = %d, want 1", len(resp.UserProfiles))
	}
}

func TestFullPeersSortedByID(t *testing.T) {
	self := testNode(1, "self")
	resp := Full(self, []state.Node{testNode(9, "nine"), testNode(3, "three"), testNode(5, "five")}, Config{}, neverOnline, tailcfg.CurrentCapabilityVersion)

	got := make([]tailcfg.NodeID, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		got = append(got, p.ID)
	}
	want := []tailcfg.NodeID{3, 5, 9}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("peer order = %v, want %v", got, want)
		}
	}
}

func TestFullUsesLegacyPacketFilterForOldClients(t *testing.T) {
	// capver 81 introduced MapResponse.PacketFilters.
	resp := Full(testNode(1, "self"), nil, Config{}, neverOnline, 80)

	if resp.PacketFilters != nil {
		t.Error("PacketFilters must not be set for pre-81 clients")
	}
	if len(resp.PacketFilter) == 0 {
		t.Error("PacketFilter must be set for pre-81 clients")
	}
}

func TestOnlineReflectsSessions(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	online := func(id state.NodeID) bool { return id == peer.ID }

	resp := Full(self, []state.Node{self, peer}, Config{}, online, tailcfg.CurrentCapabilityVersion)

	if resp.Node.Online == nil || !*resp.Node.Online {
		t.Error("the requesting node is online by construction")
	}
	if resp.Peers[0].Online == nil || !*resp.Peers[0].Online {
		t.Error("peer with a live session must be reported online")
	}
}

func TestDNSConfigOmittedWithoutDomain(t *testing.T) {
	resp := Full(testNode(1, "self"), nil, Config{}, neverOnline, tailcfg.CurrentCapabilityVersion)
	if resp.DNSConfig != nil {
		t.Errorf("dns config = %+v, want nil without a domain", resp.DNSConfig)
	}
}

func TestUpdateCarriesOnlyMutableFields(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	resp := Update(self, []state.Node{self, peer}, neverOnline)

	if resp.Node == nil || len(resp.Peers) != 1 {
		t.Fatalf("update = %+v, want self node and one peer", resp)
	}
	if resp.DNSConfig != nil || resp.DERPMap != nil || resp.Domain != "" {
		t.Error("update must not restate DNSConfig/DERPMap/Domain (nil means unchanged)")
	}
	if resp.PacketFilters != nil || resp.PacketFilter != nil {
		t.Error("update must not restate the packet filter")
	}
}
