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

func TestNormalizeDNSRecordName(t *testing.T) {
	good := map[string]string{
		"_acme-challenge.foo.example.com.": "_acme-challenge.foo.example.com",
		"FOO.Example.COM":                  "foo.example.com",
	}
	for in, want := range good {
		got, err := NormalizeDNSRecordName(in)
		if err != nil {
			t.Errorf("NormalizeDNSRecordName(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDNSRecordName(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "localhost", "-bad.example.com", "foo..example.com"} {
		if got, err := NormalizeDNSRecordName(bad); err == nil {
			t.Errorf("NormalizeDNSRecordName(%q) = %q, want an error", bad, got)
		}
	}
}

func TestNormalizeDNSRecordType(t *testing.T) {
	for in, want := range map[string]string{"": "A", "txt": "TXT", "A": "A", "AAAA": "AAAA"} {
		got, err := NormalizeDNSRecordType(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDNSRecordType(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeDNSRecordType("MX"); err == nil {
		t.Error("expected an error for an unsupported record type")
	}
}
