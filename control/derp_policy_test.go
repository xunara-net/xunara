package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestDERPPolicyApply(t *testing.T) {
	base := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1},
		2: {RegionID: 2},
	}}

	t.Run("inherit", func(t *testing.T) {
		got, err := (DERPPolicy{}).Apply(base)
		if err != nil || got != base {
			t.Fatalf("Apply = %v, %v; want the configured map unchanged", got, err)
		}
		if got, err := (DERPPolicy{}).Apply(nil); err != nil || got != nil {
			t.Fatalf("Apply(nil) = %v, %v; want nil", got, err)
		}
	})

	t.Run("none", func(t *testing.T) {
		got, err := (DERPPolicy{Mode: DERPPolicyNone}).Apply(base)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got == nil || len(got.Regions) != 0 || !got.OmitDefaultRegions {
			t.Fatalf("Apply = %+v, want a non-nil empty map", got)
		}
		// A client treats a nil Regions map as "unchanged", so the empty map
		// must survive JSON as an explicit object (upstream semantics in
		// reference/tailscale/control/controlclient/map.go).
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshalling the empty map: %v", err)
		}
		if !strings.Contains(string(raw), `"Regions":{}`) {
			t.Fatalf("marshalled = %s, want an explicit empty Regions object", raw)
		}
	})

	t.Run("regions", func(t *testing.T) {
		got, err := (DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{2}}).Apply(base)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(got.Regions) != 1 || got.Regions[2] == nil || !got.OmitDefaultRegions {
			t.Fatalf("Apply = %+v, want only region 2", got)
		}
		if len(base.Regions) != 2 {
			t.Error("Apply mutated the configured map")
		}
	})

	for name, tc := range map[string]struct {
		policy DERPPolicy
		base   *tailcfg.DERPMap
	}{
		"unknown mode":           {DERPPolicy{Mode: "sometimes"}, base},
		"regions without a list": {DERPPolicy{Mode: DERPPolicyRegions}, base},
		"regions without a map":  {DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{1}}, nil},
		"unknown region":         {DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{9}}, base},
		"ids without the mode":   {DERPPolicy{Mode: DERPPolicyNone, Regions: []int{1}}, base},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.policy.Apply(tc.base); err == nil {
				t.Fatal("Apply succeeded, want an error")
			}
		})
	}
}

func TestParseDERPPolicy(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mode, regions string
		wantMode      DERPPolicyMode
		wantRegions   []int
		wantErr       bool
	}{
		{name: "inherit", wantMode: DERPPolicyInherit},
		{name: "none", mode: " none ", wantMode: DERPPolicyNone},
		{name: "regions", mode: "regions", regions: "1, 2,3", wantMode: DERPPolicyRegions, wantRegions: []int{1, 2, 3}},
		{name: "regions without ids", mode: "regions", wantMode: DERPPolicyRegions},
		{name: "zero id", mode: "regions", regions: "0", wantErr: true},
		{name: "not a number", mode: "regions", regions: "two", wantErr: true},
		{name: "ids without the mode", mode: "none", regions: "1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDERPPolicy(tc.mode, tc.regions)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDERPPolicy(%q, %q) = %+v, want an error", tc.mode, tc.regions, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDERPPolicy(%q, %q): %v", tc.mode, tc.regions, err)
			}
			if got.Mode != tc.wantMode || len(got.Regions) != len(tc.wantRegions) {
				t.Fatalf("ParseDERPPolicy = %+v, want mode %q regions %v", got, tc.wantMode, tc.wantRegions)
			}
			for i, id := range tc.wantRegions {
				if got.Regions[i] != id {
					t.Fatalf("regions = %v, want %v", got.Regions, tc.wantRegions)
				}
			}
		})
	}
}

// TestDERPPolicyFiltersServedMap checks the half of the policy clients see: the
// map response only lists the allowed regions, and a node homed in a filtered
// region is re-homed.
func TestDERPPolicyFiltersServedMap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1},
			2: {RegionID: 2},
		}},
		DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{1}},
	})
	node := seedTestNode(t, s)

	full := s.fullMap(node, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	if full.DERPMap == nil || len(full.DERPMap.Regions) != 1 || full.DERPMap.Regions[1] == nil {
		t.Fatalf("served DERP map = %+v, want only region 1", full.DERPMap)
	}
	if _, ok := full.DERPMap.Regions[2]; ok {
		t.Error("served DERP map still lists the filtered region 2")
	}
	if got := s.derpRegionsServed(); got != 1 {
		t.Errorf("derpRegionsServed = %d, want 1", got)
	}
	if got := s.DERPMap(); got == nil || len(got.Regions) != 1 {
		t.Errorf("DERPMap() = %+v, want the served map", got)
	}

	// The only served region is adopted without a latency hunt.
	node = s.recordMapRequest(node, tailcfg.MapRequest{})
	if node.HomeDERP != 1 {
		t.Fatalf("HomeDERP = %d, want the only served region 1", node.HomeDERP)
	}

	// A node left homed in a region the policy no longer serves is re-homed.
	node.HomeDERP = 2
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("updating node: %v", err)
	}
	node = s.recordMapRequest(node, tailcfg.MapRequest{})
	if node.HomeDERP != 1 {
		t.Errorf("HomeDERP = %d, want the stale region 2 replaced by 1", node.HomeDERP)
	}
}

// TestDERPPolicyNoneDisablesDERP checks the enforceable half: with DERP
// disabled the served map is empty and the admission controller refuses even
// registered nodes.
func TestDERPPolicyNoneDisablesDERP(t *testing.T) {
	s := newServerWithConfig(t, Config{
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1},
		}},
		DERPPolicy: DERPPolicy{Mode: DERPPolicyNone},
	})
	hs := newTestHTTPServer(t, s)
	node := seedTestNode(t, s)

	full := s.fullMap(node, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	if full.DERPMap == nil || len(full.DERPMap.Regions) != 0 {
		t.Fatalf("served DERP map = %+v, want none", full.DERPMap)
	}
	if got := s.derpRegionsServed(); got != 0 {
		t.Errorf("derpRegionsServed = %d, want 0", got)
	}

	res, status := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{NodePublic: node.NodeKey})
	if status != http.StatusOK || res.Allow {
		t.Fatalf("admission = %+v, %d; want a refusal under policy none", res, status)
	}

	// And a stale home region does not survive the next map request.
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("updating node: %v", err)
	}
	node.HomeDERP = 1
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("updating node: %v", err)
	}
	node = s.recordMapRequest(node, tailcfg.MapRequest{})
	if node.HomeDERP != 0 {
		t.Errorf("HomeDERP = %d, want 0 with DERP disabled", node.HomeDERP)
	}
}

// TestDERPPolicyRegionsAdmission checks that a node homed in a filtered region
// is refused while the served region keeps working.
func TestDERPPolicyRegionsAdmission(t *testing.T) {
	s := newServerWithConfig(t, Config{
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1},
			2: {RegionID: 2},
		}},
		DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{1}},
	})
	hs := newTestHTTPServer(t, s)
	node := seedTestNode(t, s)

	// A node that has not chosen a region yet is admitted: it can only reach
	// the regions the served map advertises.
	if res, _ := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{NodePublic: node.NodeKey}); !res.Allow {
		t.Fatal("a node without a home region was refused")
	}

	for _, tc := range []struct {
		home      tailcfg.DERPRegionID
		wantAllow bool
	}{
		{home: 1, wantAllow: true},
		{home: 2, wantAllow: false},
	} {
		node.HomeDERP = tc.home
		if err := s.store.UpdateNode(node); err != nil {
			t.Fatalf("updating node: %v", err)
		}
		res, _ := admit(t, hs.URL, tailcfg.DERPAdmitClientRequest{NodePublic: node.NodeKey})
		if res.Allow != tc.wantAllow {
			t.Errorf("node homed in %d: allow = %v, want %v", tc.home, res.Allow, tc.wantAllow)
		}
	}
}

// TestNewRejectsBrokenDERPPolicy checks that a policy naming an unknown region
// stops the server instead of silently serving a smaller tailnet.
func TestNewRejectsBrokenDERPPolicy(t *testing.T) {
	_, err := New(Config{
		StateDir: t.TempDir(),
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1},
		}},
		DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{7}},
	})
	if err == nil {
		t.Fatal("New accepted a DERP policy naming a region the map does not contain")
	}
}

// TestNetmapCarriesDERPPolicy drives the policy through a real registration and
// map request, so the bytes a client receives are checked, not just the
// in-process map.
func TestNetmapCarriesDERPPolicy(t *testing.T) {
	twoRegions := func() *tailcfg.DERPMap {
		return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1},
			2: {RegionID: 2},
		}}
	}

	t.Run("regions", func(t *testing.T) {
		s := newServerWithConfig(t, Config{
			DERPMap:    twoRegions(),
			DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{1}},
		})
		hs := newTestHTTPServer(t, s)
		conn, client, nodeKey := registerNode(t, s, hs, "derp-node")
		defer conn.Close()

		msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: nodeKey.Public(),
		}), "")

		if msg.DERPMap == nil || len(msg.DERPMap.Regions) != 1 || msg.DERPMap.Regions[1] == nil {
			t.Fatalf("netmap DERP map = %+v, want only region 1", msg.DERPMap)
		}
		if _, ok := msg.DERPMap.Regions[2]; ok {
			t.Error("netmap still advertises the filtered region 2")
		}
	})

	t.Run("none", func(t *testing.T) {
		s := newServerWithConfig(t, Config{
			DERPMap:    twoRegions(),
			DERPPolicy: DERPPolicy{Mode: DERPPolicyNone},
		})
		hs := newTestHTTPServer(t, s)
		conn, client, nodeKey := registerNode(t, s, hs, "derp-node")
		defer conn.Close()

		msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: nodeKey.Public(),
		}), "")

		// The map must be present (a nil map means "unchanged" to a client)
		// and carry an explicit empty region set.
		if msg.DERPMap == nil {
			t.Fatal("netmap omits the DERP map; clients would keep the previous one")
		}
		if msg.DERPMap.Regions == nil || len(msg.DERPMap.Regions) != 0 {
			t.Fatalf("netmap DERP map = %+v, want an explicit empty region set", msg.DERPMap)
		}
	})
}
