package state

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
)

func TestEffectiveRoutes(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/8")
	other := netip.MustParsePrefix("192.168.0.0/16")

	n := Node{
		Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet, ExitRouteV4}},
		ApprovedRoutes: []netip.Prefix{ExitRouteV4, other},
	}

	if got, want := n.AnnouncedRoutes(), []netip.Prefix{subnet, ExitRouteV4}; !slices.Equal(got, want) {
		t.Errorf("AnnouncedRoutes = %v, want %v", got, want)
	}

	// Only the announced-and-approved intersection takes effect.
	if got, want := n.EffectiveRoutes(), []netip.Prefix{ExitRouteV4}; !slices.Equal(got, want) {
		t.Errorf("EffectiveRoutes = %v, want %v", got, want)
	}

	n.ApprovedRoutes = []netip.Prefix{subnet, ExitRouteV4}
	if got, want := n.EffectiveRoutes(), []netip.Prefix{ExitRouteV4, subnet}; !slices.Equal(got, want) {
		t.Errorf("EffectiveRoutes = %v, want %v", got, want)
	}
	if !n.IsExitNode() {
		t.Error("IsExitNode = false for a node serving the default route")
	}

	// A node without Hostinfo has neither announcements nor effective routes.
	if bare := (Node{}); len(bare.AnnouncedRoutes()) != 0 || len(bare.EffectiveRoutes()) != 0 || bare.IsExitNode() {
		t.Error("zero node should have no routes")
	}
}

func TestIsExitRoute(t *testing.T) {
	for _, p := range []netip.Prefix{ExitRouteV4, ExitRouteV6} {
		if !IsExitRoute(p) {
			t.Errorf("IsExitRoute(%s) = false", p)
		}
	}
	if IsExitRoute(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("IsExitRoute(10.0.0.0/8) = true")
	}
}
