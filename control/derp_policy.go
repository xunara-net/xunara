package control

import (
	"fmt"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"
)

// Organization-level DERP policy (M7b).
//
// The policy decides which DERP regions an organization's clients are told
// about, and which of that organization's nodes the DERP admission controller
// (control/derp.go) lets in. Both checks live inside the organization's own
// Server, so one tenant's policy never changes another's.
//
// Serving a filtered map is advisory: a client whose operator hard-codes a
// public DERP node can still reach it. The admission controller is the
// enforceable half, and it only covers the relay Xunara runs (Xunara Veil).

// DERPPolicyMode selects how the configured DERP map is served.
type DERPPolicyMode string

const (
	// DERPPolicyInherit serves the configured map unchanged. It is the zero
	// value, so deployments that set no policy keep their behaviour.
	DERPPolicyInherit DERPPolicyMode = ""
	// DERPPolicyNone advertises no DERP regions: clients fall back to direct
	// connections, and this organization's nodes are refused by the DERP
	// admission controller.
	DERPPolicyNone DERPPolicyMode = "none"
	// DERPPolicyRegions serves only the listed region IDs. A listed region
	// missing from the configured map is an error, so a typo cannot silently
	// disable one.
	DERPPolicyRegions DERPPolicyMode = "regions"
)

// DERPPolicy is one organization's DERP restriction.
type DERPPolicy struct {
	Mode DERPPolicyMode
	// Regions are the allowed region IDs, required for DERPPolicyRegions.
	Regions []int
}

// ParseDERPPolicy builds a policy from command-line values: mode is "" (inherit),
// "none" or "regions"; regions is a comma-separated region ID list.
func ParseDERPPolicy(mode, regions string) (DERPPolicy, error) {
	policy := DERPPolicy{Mode: DERPPolicyMode(strings.TrimSpace(mode))}
	for _, raw := range strings.Split(regions, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := strconv.Atoi(raw)
		if err != nil || id <= 0 {
			return DERPPolicy{}, fmt.Errorf("control: invalid DERP region %q", raw)
		}
		policy.Regions = append(policy.Regions, id)
	}
	if policy.Mode != DERPPolicyRegions && len(policy.Regions) > 0 {
		return DERPPolicy{}, fmt.Errorf("control: DERP regions are only meaningful with policy mode %q", DERPPolicyRegions)
	}
	return policy, nil
}

// Apply validates the policy against the configured map and returns the map
// this organization's clients must be served. A nil result means "no map to
// advertise": either the deployment configured none, or the policy serves
// none. The result may share region definitions with base; callers must not
// mutate it.
func (p DERPPolicy) Apply(base *tailcfg.DERPMap) (*tailcfg.DERPMap, error) {
	if p.Mode != DERPPolicyRegions && len(p.Regions) > 0 {
		return nil, fmt.Errorf("control: DERP regions are only meaningful with policy mode %q", DERPPolicyRegions)
	}
	switch p.Mode {
	case DERPPolicyInherit:
		return base, nil

	case DERPPolicyNone:
		// An empty but non-nil region map is what tells a client "no DERP
		// servers": tailcfg.DERPMap.Regions has no omitempty, so it is
		// serialised as "Regions":{}, and clients treat a nil map as
		// "unchanged" (reference/tailscale/control/controlclient/map.go).
		return &tailcfg.DERPMap{
			Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
			OmitDefaultRegions: true,
		}, nil

	case DERPPolicyRegions:
		if len(p.Regions) == 0 {
			return nil, fmt.Errorf("control: DERP policy %q needs at least one region", DERPPolicyRegions)
		}
		if base == nil || len(base.Regions) == 0 {
			return nil, fmt.Errorf("control: DERP policy %q needs a configured DERP map", DERPPolicyRegions)
		}
		regions := make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion, len(p.Regions))
		for _, id := range p.Regions {
			region, ok := base.Regions[tailcfg.DERPRegionID(id)]
			if !ok || region == nil {
				return nil, fmt.Errorf("control: DERP region %d is not in the configured DERP map", id)
			}
			regions[tailcfg.DERPRegionID(id)] = region
		}
		return &tailcfg.DERPMap{Regions: regions, OmitDefaultRegions: true}, nil

	default:
		return nil, fmt.Errorf("control: unknown DERP policy mode %q", p.Mode)
	}
}

// admits reports whether the policy admits a node to DERP. A node that has not
// chosen a home region yet is admitted in "regions" mode: it can only reach the
// regions the served map advertises. In "none" mode nothing is admitted.
func (p DERPPolicy) admits(homeDERP tailcfg.DERPRegionID, known func(tailcfg.DERPRegionID) bool) bool {
	switch p.Mode {
	case DERPPolicyNone:
		return false
	case DERPPolicyRegions:
		return homeDERP == 0 || known(homeDERP)
	default:
		return true
	}
}
