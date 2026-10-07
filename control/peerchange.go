package control

import (
	"bytes"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// tailcfgNodeFields returns the field names of tailcfg.Node.
//
// [peerChangeDiff] switches over this list, so a tailscale.com dependency bump
// that adds a field cannot be forgotten silently: the guard test fails, and
// until the field is classified every peer carrying a differing value falls
// back to a full node.
var tailcfgNodeFields = sync.OnceValue(func() []string {
	rt := reflect.TypeFor[tailcfg.Node]()
	names := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		names = append(names, rt.Field(i).Name)
	}
	return names
})

// peerChangeDiff computes the tailcfg.PeerChange that expresses every
// difference between was and now that the wire format can carry.
//
// ok is false when some difference cannot be expressed as a PeerChange: the
// caller must send the whole node instead. ok true with a nil change means the
// nodes are identical in every field a client can observe.
//
// The patchable set and the "send the whole node" set mirror upstream's
// controlclient.peerChangeDiff
// (reference/tailscale/control/controlclient/map.go). Unlike upstream this
// function fails closed on tailcfg.Node fields it does not know instead of
// panicking, so an unreviewed dependency bump can only cost efficiency, never
// correctness.
func peerChangeDiff(was, now *tailcfg.Node) (_ *tailcfg.PeerChange, ok bool) {
	var pc *tailcfg.PeerChange
	change := func() *tailcfg.PeerChange {
		if pc == nil {
			pc = new(tailcfg.PeerChange)
		}
		return pc
	}

	for _, field := range tailcfgNodeFields() {
		switch field {
		default:
			// Fail closed: an unhandled field may have changed in a way this
			// function cannot prove is patchable.
			return nil, false

		// Fields that identify the node and must never move between IDs: a
		// difference here means the caller is diffing the wrong nodes.
		case "ID":
			if was.ID != now.ID {
				return nil, false
			}
		case "StableID":
			if was.StableID != now.StableID {
				return nil, false
			}

		// Name, ownership and machine identity are not carried by PeerChange;
		// a change forces the whole node (and a client rebuild).
		case "Name":
			if was.Name != now.Name {
				return nil, false
			}
		case "User":
			if was.User != now.User {
				return nil, false
			}
		case "Sharer":
			if was.Sharer != now.Sharer {
				return nil, false
			}
		case "Machine":
			if was.Machine != now.Machine {
				return nil, false
			}

		// Key material rotates in place and is patchable.
		case "Key":
			if was.Key != now.Key {
				change().Key = &now.Key
			}
		case "KeyExpiry":
			if !was.KeyExpiry.Equal(now.KeyExpiry) {
				expiry := now.KeyExpiry
				change().KeyExpiry = &expiry
			}
		case "KeySignature":
			if !bytes.Equal(was.KeySignature, now.KeySignature) {
				if len(now.KeySignature) == 0 {
					// PeerChange.KeySignature is omitempty, so clearing it is
					// not expressible.
					return nil, false
				}
				change().KeySignature = slices.Clone(now.KeySignature)
			}
		case "DiscoKey":
			if was.DiscoKey != now.DiscoKey {
				change().DiscoKey = &now.DiscoKey
			}

		// Addressing changes are structural: routes and peers key off them,
		// so the client must process the whole node.
		case "Addresses":
			if !slices.Equal(was.Addresses, now.Addresses) {
				return nil, false
			}
		case "AllowedIPs":
			if !slices.Equal(was.AllowedIPs, now.AllowedIPs) {
				return nil, false
			}
		case "PrimaryRoutes":
			if !slices.Equal(was.PrimaryRoutes, now.PrimaryRoutes) {
				return nil, false
			}

		// A peer's observed endpoints and DERP home change often and are the
		// main reason patches exist.
		case "Endpoints":
			if !slices.Equal(was.Endpoints, now.Endpoints) {
				if len(now.Endpoints) == 0 {
					// PeerChange.Endpoints is omitempty and clients ignore
					// empty values, so an emptied list needs the whole node.
					return nil, false
				}
				change().Endpoints = slices.Clone(now.Endpoints)
			}
		case "LegacyDERPString":
			// Deprecated pre-HomeDERP form; control never sends it.
			if was.LegacyDERPString != now.LegacyDERPString {
				return nil, false
			}
		case "HomeDERP":
			if was.HomeDERP != now.HomeDERP {
				if now.HomeDERP == 0 {
					// PeerChange.DERPRegion is omitzero and clients ignore
					// zero, so un-homing needs the whole node.
					return nil, false
				}
				change().DERPRegion = now.HomeDERP
			}

		// Hostinfo changes (hostname, OS, interfaces) affect peers' view of
		// the node as a whole.
		case "Hostinfo":
			if was.Hostinfo.Valid() != now.Hostinfo.Valid() {
				return nil, false
			}
			if was.Hostinfo.Valid() && !was.Hostinfo.Equal(now.Hostinfo) {
				return nil, false
			}

		case "Created":
			if !was.Created.Equal(now.Created) {
				return nil, false
			}
		case "Cap":
			if was.Cap != now.Cap {
				if now.Cap == 0 {
					// PeerChange.Cap is omitzero and clients ignore zero.
					return nil, false
				}
				change().Cap = now.Cap
			}
		case "Tags":
			if !slices.Equal(was.Tags, now.Tags) {
				return nil, false
			}
		case "LastSeen":
			switch {
			case was.LastSeen == nil && now.LastSeen == nil:
			case was.LastSeen == nil:
				seen := *now.LastSeen
				change().LastSeen = &seen
			case now.LastSeen == nil:
				// PeerChange cannot clear LastSeen back to unknown.
				return nil, false
			case !was.LastSeen.Equal(*now.LastSeen):
				seen := *now.LastSeen
				change().LastSeen = &seen
			}
		case "Online":
			switch {
			case was.Online == nil && now.Online == nil:
			case was.Online == nil:
				online := *now.Online
				change().Online = &online
			case now.Online == nil:
				// PeerChange cannot clear Online back to unknown.
				return nil, false
			case *was.Online != *now.Online:
				online := *now.Online
				change().Online = &online
			}

		case "MachineAuthorized":
			if was.MachineAuthorized != now.MachineAuthorized {
				return nil, false
			}
		case "Capabilities":
			// Deprecated in favor of CapMap; control never sends it.
			if !slices.Equal(was.Capabilities, now.Capabilities) {
				return nil, false
			}
		case "CapMap":
			if !capMapEqual(was.CapMap, now.CapMap) {
				if len(now.CapMap) == 0 {
					// PeerChange.CapMap is omitempty, so clearing the map is
					// not expressible.
					return nil, false
				}
				change().CapMap = maps.Clone(now.CapMap)
			}
		case "UnsignedPeerAPIOnly":
			if was.UnsignedPeerAPIOnly != now.UnsignedPeerAPIOnly {
				return nil, false
			}
		case "computedHostIfDifferent", "ComputedName", "ComputedNameWithHost":
			// Display names are computed client-side from Name and Hostinfo
			// (upstream skips them here too).
			continue
		case "DataPlaneAuditLogID":
			if was.DataPlaneAuditLogID != now.DataPlaneAuditLogID {
				return nil, false
			}
		case "Expired":
			if was.Expired != now.Expired {
				return nil, false
			}
		case "SelfNodeV4MasqAddrForThisPeer":
			if !addrPtrEqual(was.SelfNodeV4MasqAddrForThisPeer, now.SelfNodeV4MasqAddrForThisPeer) {
				return nil, false
			}
		case "SelfNodeV6MasqAddrForThisPeer":
			if !addrPtrEqual(was.SelfNodeV6MasqAddrForThisPeer, now.SelfNodeV6MasqAddrForThisPeer) {
				return nil, false
			}
		case "IsWireGuardOnly":
			if was.IsWireGuardOnly != now.IsWireGuardOnly {
				return nil, false
			}
		case "IsJailed":
			if was.IsJailed != now.IsJailed {
				return nil, false
			}
		case "ExitNodeDNSResolvers":
			if !resolverSlicesEqual(was.ExitNodeDNSResolvers, now.ExitNodeDNSResolvers) {
				return nil, false
			}
		case "StableTailnetID":
			// Control populates this only for the self node.
			if was.StableTailnetID != now.StableTailnetID {
				return nil, false
			}
		}
	}

	if pc != nil {
		pc.NodeID = now.ID
	}
	return pc, true
}

// capMapEqual reports whether two capability maps carry the same capabilities
// with the same arguments.
func capMapEqual(a, b tailcfg.NodeCapMap) bool {
	if len(a) != len(b) {
		return false
	}
	for capability, values := range a {
		other, ok := b[capability]
		if !ok || !slices.Equal(values, other) {
			return false
		}
	}
	return true
}

// addrPtrEqual compares optional addresses by value, treating nil and non-nil
// as different.
func addrPtrEqual(a, b *netip.Addr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// resolverSlicesEqual compares resolver lists entry by entry.
func resolverSlicesEqual(a, b []*dnstype.Resolver) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		switch {
		case a[i] == nil || b[i] == nil:
			if a[i] != b[i] {
				return false
			}
		case !a[i].Equal(b[i]):
			return false
		}
	}
	return true
}
