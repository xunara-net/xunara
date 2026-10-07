package state

import (
	"net/netip"
	"slices"
	"testing"
)

func prefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}

func TestApplyRouteApproval(t *testing.T) {
	tests := []struct {
		name      string
		approved  []netip.Prefix
		approve   []netip.Prefix
		unapprove []netip.Prefix
		want      []netip.Prefix
	}{
		{
			name:     "approve appends",
			approved: prefixes("10.0.0.0/8"),
			approve:  prefixes("192.168.0.0/16"),
			want:     prefixes("10.0.0.0/8", "192.168.0.0/16"),
		},
		{
			name:      "unapprove removes",
			approved:  prefixes("10.0.0.0/8", "192.168.0.0/16"),
			unapprove: prefixes("10.0.0.0/8"),
			want:      prefixes("192.168.0.0/16"),
		},
		{
			name:      "approve wins over unapprove",
			approve:   prefixes("10.0.0.0/8"),
			unapprove: prefixes("10.0.0.0/8"),
			want:      prefixes("10.0.0.0/8"),
		},
		{
			name:     "duplicates collapse",
			approved: prefixes("10.0.0.0/8"),
			approve:  prefixes("10.0.0.0/8", "10.0.0.0/8"),
			want:     prefixes("10.0.0.0/8"),
		},
		{
			name:      "empty result is nil",
			approved:  prefixes("10.0.0.0/8"),
			unapprove: prefixes("10.0.0.0/8"),
			want:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyRouteApproval(tc.approved, tc.approve, tc.unapprove)
			if !slices.Equal(got, tc.want) {
				t.Errorf("ApplyRouteApproval = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteDelta(t *testing.T) {
	added, removed := RouteDelta(
		prefixes("10.0.0.0/8", "192.168.0.0/16"),
		prefixes("10.0.0.0/8", "172.16.0.0/12"),
	)
	if len(added) != 1 || added[0].String() != "172.16.0.0/12" {
		t.Errorf("added = %v", added)
	}
	if len(removed) != 1 || removed[0].String() != "192.168.0.0/16" {
		t.Errorf("removed = %v", removed)
	}
}
