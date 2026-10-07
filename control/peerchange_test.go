package control

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestPeerChangeDiffPatchableFields(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.7:41641")
	seen := time.Date(2026, 10, 7, 1, 2, 3, 0, time.UTC)
	expiry := seen.Add(24 * time.Hour)
	online := true
	rotatedKey := key.NewNode().Public()
	rotatedDisco := key.NewDisco().Public()
	capMap := tailcfg.NodeCapMap{"example.com/cap/thing": {tailcfg.RawMessage("true")}}

	tests := []struct {
		name   string
		mutate func(n *tailcfg.Node)
		check  func(t *testing.T, pc *tailcfg.PeerChange)
	}{
		{
			name:   "endpoints",
			mutate: func(n *tailcfg.Node) { n.Endpoints = []netip.AddrPort{endpoint} },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if !slices.Equal(pc.Endpoints, []netip.AddrPort{endpoint}) {
					t.Errorf("Endpoints = %v, want %v", pc.Endpoints, endpoint)
				}
			},
		},
		{
			name:   "home derp",
			mutate: func(n *tailcfg.Node) { n.HomeDERP = 12 },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.DERPRegion != 12 {
					t.Errorf("DERPRegion = %d, want 12", pc.DERPRegion)
				}
			},
		},
		{
			name:   "online",
			mutate: func(n *tailcfg.Node) { n.Online = &online },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.Online == nil || *pc.Online != online {
					t.Errorf("Online = %v, want %v", pc.Online, online)
				}
			},
		},
		{
			name:   "last seen",
			mutate: func(n *tailcfg.Node) { n.LastSeen = &seen },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.LastSeen == nil || !pc.LastSeen.Equal(seen) {
					t.Errorf("LastSeen = %v, want %v", pc.LastSeen, seen)
				}
			},
		},
		{
			name:   "capability version",
			mutate: func(n *tailcfg.Node) { n.Cap = 42 },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.Cap != 42 {
					t.Errorf("Cap = %d, want 42", pc.Cap)
				}
			},
		},
		{
			name:   "cap map",
			mutate: func(n *tailcfg.Node) { n.CapMap = capMap },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if !capMapEqual(pc.CapMap, capMap) {
					t.Errorf("CapMap = %v, want %v", pc.CapMap, capMap)
				}
			},
		},
		{
			name:   "key rotation",
			mutate: func(n *tailcfg.Node) { n.Key = rotatedKey },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.Key == nil || *pc.Key != rotatedKey {
					t.Errorf("Key = %v, want %v", pc.Key, rotatedKey)
				}
			},
		},
		{
			name:   "key expiry",
			mutate: func(n *tailcfg.Node) { n.KeyExpiry = expiry },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.KeyExpiry == nil || !pc.KeyExpiry.Equal(expiry) {
					t.Errorf("KeyExpiry = %v, want %v", pc.KeyExpiry, expiry)
				}
			},
		},
		{
			name:   "key signature",
			mutate: func(n *tailcfg.Node) { n.KeySignature = []byte("sig") },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if string(pc.KeySignature) != "sig" {
					t.Errorf("KeySignature = %q, want sig", pc.KeySignature)
				}
			},
		},
		{
			name:   "disco key",
			mutate: func(n *tailcfg.Node) { n.DiscoKey = rotatedDisco },
			check: func(t *testing.T, pc *tailcfg.PeerChange) {
				if pc.DiscoKey == nil || *pc.DiscoKey != rotatedDisco {
					t.Errorf("DiscoKey = %v, want %v", pc.DiscoKey, rotatedDisco)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			was := sessionNode(7, "peer")
			now := *was
			tt.mutate(&now)

			pc, ok := peerChangeDiff(was, &now)
			if !ok {
				t.Fatal("peerChangeDiff refused to patch a patchable field")
			}
			if pc == nil {
				t.Fatal("peerChangeDiff returned no change for a changed field")
			}
			if pc.NodeID != 7 {
				t.Errorf("NodeID = %d, want 7", pc.NodeID)
			}
			tt.check(t, pc)
		})
	}
}

func TestPeerChangeDiffNonPatchableFields(t *testing.T) {
	withEndpoints := sessionNode(7, "peer")
	withEndpoints.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}
	withHomeDERP := sessionNode(7, "peer")
	withHomeDERP.HomeDERP = 12
	withOnline := sessionNode(7, "peer")
	withOnline.Online = new(bool)
	withLastSeen := sessionNode(7, "peer")
	seen := time.Date(2026, 10, 7, 1, 2, 3, 0, time.UTC)
	withLastSeen.LastSeen = &seen
	withCap := sessionNode(7, "peer")
	withCap.Cap = 30
	withCapMap := sessionNode(7, "peer")
	withCapMap.CapMap = tailcfg.NodeCapMap{"example.com/cap/thing": nil}
	withName := sessionNode(7, "peer")
	withName.Name = "renamed."
	withAddresses := sessionNode(7, "peer")
	withAddresses.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}
	withAllowedIPs := sessionNode(7, "peer")
	withAllowedIPs.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}
	withPrimaryRoutes := sessionNode(7, "peer")
	withPrimaryRoutes.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	withHostinfo := sessionNode(7, "peer")
	withHostinfo.Hostinfo = (&tailcfg.Hostinfo{Hostname: "peer"}).View()
	withTags := sessionNode(7, "peer")
	withTags.Tags = []string{"tag:prod"}
	withExpired := sessionNode(7, "peer")
	withExpired.Expired = true
	withMachine := sessionNode(7, "peer")
	withMachine.Machine = key.NewMachine().Public()

	tests := []struct {
		name string
		was  *tailcfg.Node
		now  *tailcfg.Node
	}{
		{"name", sessionNode(7, "peer"), withName},
		{"stable id", sessionNode(7, "peer"), func() *tailcfg.Node {
			n := sessionNode(7, "peer")
			n.StableID = "other"
			return n
		}()},
		{"machine", sessionNode(7, "peer"), withMachine},
		{"addresses", sessionNode(7, "peer"), withAddresses},
		{"allowed ips", sessionNode(7, "peer"), withAllowedIPs},
		{"primary routes", sessionNode(7, "peer"), withPrimaryRoutes},
		{"hostinfo added", sessionNode(7, "peer"), withHostinfo},
		{"hostinfo removed", withHostinfo, sessionNode(7, "peer")},
		{"tags", sessionNode(7, "peer"), withTags},
		{"expired", sessionNode(7, "peer"), withExpired},
		{"endpoints cleared", withEndpoints, sessionNode(7, "peer")},
		{"home derp cleared", withHomeDERP, sessionNode(7, "peer")},
		{"online cleared", withOnline, sessionNode(7, "peer")},
		{"last seen cleared", withLastSeen, sessionNode(7, "peer")},
		{"cap cleared", withCap, sessionNode(7, "peer")},
		{"cap map cleared", withCapMap, sessionNode(7, "peer")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := peerChangeDiff(tt.was, tt.now); ok {
				t.Error("peerChangeDiff claimed an unpatchable difference is patchable")
			}
		})
	}
}

// TestPeerChangeDiffHandlesEveryNodeField guards against a tailscale.com
// dependency bump that adds a tailcfg.Node field: peerChangeDiff fails closed
// on unknown fields, so without an update here every peer change would silently
// fall back to a full node.
func TestPeerChangeDiffHandlesEveryNodeField(t *testing.T) {
	pc, ok := peerChangeDiff(&tailcfg.Node{}, &tailcfg.Node{})
	if !ok {
		rt := reflect.TypeFor[tailcfg.Node]()
		names := make([]string, 0, rt.NumField())
		for i := range rt.NumField() {
			names = append(names, rt.Field(i).Name)
		}
		t.Fatalf("peerChangeDiff does not handle every tailcfg.Node field; update the switch in control/peerchange.go (fields: %v)", names)
	}
	if pc != nil {
		t.Errorf("identical nodes produced a change: %+v", pc)
	}
}

func TestPeerChangeDiffIdentical(t *testing.T) {
	was := sessionNode(7, "peer")
	now := *was
	if pc, ok := peerChangeDiff(was, &now); !ok || pc != nil {
		t.Errorf("identical nodes: pc = %+v, ok = %v; want nil, true", pc, ok)
	}
}
