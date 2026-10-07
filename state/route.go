package state

import (
	"net/netip"
	"slices"
)

// ApplyRouteApproval computes the approved route set after approving and
// unapproving prefixes.
//
// Unapproval is applied first, then approval, so a prefix listed in both takes
// the approval path; duplicates are collapsed. The original order is kept and
// new approvals are appended, which keeps CLI output and audit diffs stable.
func ApplyRouteApproval(approved, approve, unapprove []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(approved)+len(approve))
	for _, r := range approved {
		if slices.Contains(unapprove, r) || slices.Contains(out, r) {
			continue
		}
		out = append(out, r)
	}
	for _, r := range approve {
		if slices.Contains(out, r) {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RouteDelta reports which prefixes were added and removed.
func RouteDelta(before, after []netip.Prefix) (added, removed []netip.Prefix) {
	for _, r := range after {
		if !slices.Contains(before, r) {
			added = append(added, r)
		}
	}
	for _, r := range before {
		if !slices.Contains(after, r) {
			removed = append(removed, r)
		}
	}
	return added, removed
}
