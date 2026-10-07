// Package mapper builds the tailnet map (the "netmap") that the control plane
// sends to clients.
//
// The wire types are the authority and live in tailscale.com/tailcfg; this
// package only decides what goes in them. It is deliberately pure — node state
// in, wire types out — so it can be unit-tested without a server.
//
// Reference: reference/headscale/hscontrol/mapper.
package mapper

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/state"
)

// packetFiltersCapVer is the capability version that introduced the
// incremental MapResponse.PacketFilters map (2023-11-17).
const packetFiltersCapVer tailcfg.CapabilityVersion = 81

// OnlineFunc reports whether a node currently holds a live control session.
type OnlineFunc func(state.NodeID) bool

// Config carries the tailnet-wide values the mapper needs.
type Config struct {
	// Domain is the MagicDNS domain of the tailnet, without a trailing dot.
	// Empty disables MagicDNS in the netmap.
	Domain string

	// DERPMap is advertised to clients when non-nil.
	DERPMap *tailcfg.DERPMap
}

// Full builds the first MapResponse of a session: everything a client needs to
// construct its netmap.
//
// nodes must include the requesting node; it is filtered out of Peers.
func Full(self state.Node, nodes []state.Node, cfg Config, online OnlineFunc, capVer tailcfg.CapabilityVersion) *tailcfg.MapResponse {
	resp := &tailcfg.MapResponse{
		Node:         Node(self, true, online),
		Peers:        peerNodes(self, nodes, online),
		Domain:       cfg.Domain,
		DNSConfig:    dnsConfig(cfg),
		DERPMap:      cfg.DERPMap,
		UserProfiles: userProfiles(self, nodes),
	}
	setPacketFilters(resp, capVer)
	return resp
}

// Update builds a MapResponse for a netmap change.
//
// Only fields that can change are set: nil means "unchanged" on the client, so
// DNSConfig, DERPMap, Domain and the packet filter are left alone.
func Update(self state.Node, nodes []state.Node, online OnlineFunc) *tailcfg.MapResponse {
	return &tailcfg.MapResponse{
		Node:         Node(self, true, online),
		Peers:        peerNodes(self, nodes, online),
		UserProfiles: userProfiles(self, nodes),
	}
}

// Node converts a stored node into its wire representation.
func Node(n state.Node, self bool, online OnlineFunc) *tailcfg.Node {
	addresses := make([]netip.Prefix, 0, 2)
	if n.IPv4.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv4, n.IPv4.BitLen()))
	}
	if n.IPv6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv6, n.IPv6.BitLen()))
	}

	out := &tailcfg.Node{
		ID:         tailcfg.NodeID(n.ID),
		StableID:   tailcfg.StableNodeID(n.StableID),
		Name:       n.FQDN(),
		User:       n.UserID,
		Key:        n.NodeKey,
		KeyExpiry:  n.Expiry,
		Machine:    n.MachineKey,
		DiscoKey:   n.DiscoKey,
		Addresses:  addresses,
		AllowedIPs: addresses,
		Endpoints:  slices.Clone(n.Endpoints),
		HomeDERP:   n.HomeDERP,
		Created:    n.Created,
		Cap:        n.CapVer,
		LastSeen:   n.LastSeen,
	}

	if n.Hostinfo != nil {
		out.Hostinfo = n.Hostinfo.View()
	}

	// The requesting node is online by construction; peers are online when they
	// hold a live control session.
	out.Online = boolPtr(self || online(n.ID))

	return out
}

// peerNodes converts every node except self, sorted by ID as the wire requires.
func peerNodes(self state.Node, nodes []state.Node, online OnlineFunc) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		out = append(out, Node(n, false, online))
	}
	slices.SortFunc(out, func(a, b *tailcfg.Node) int {
		return int(a.ID) - int(b.ID)
	})
	return out
}

// userProfiles builds the profiles for the requesting node and its peers,
// sorted by user ID as the wire requires.
func userProfiles(self state.Node, nodes []state.Node) []tailcfg.UserProfile {
	seen := make(map[tailcfg.UserID]bool)
	out := make([]tailcfg.UserProfile, 0, len(nodes)+1)

	add := func(id tailcfg.UserID) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, state.DefaultUserProfile(id))
	}

	add(self.UserID)
	for _, n := range nodes {
		add(n.UserID)
	}

	slices.SortFunc(out, func(a, b tailcfg.UserProfile) int {
		return int(a.ID) - int(b.ID)
	})
	return out
}

// dnsConfig returns the MagicDNS configuration, or nil when the tailnet has no
// domain configured (nil means "unchanged"/"none" to the client).
func dnsConfig(cfg Config) *tailcfg.DNSConfig {
	if cfg.Domain == "" {
		return nil
	}
	return &tailcfg.DNSConfig{
		Domains: []string{cfg.Domain},
		Proxied: true,
	}
}

// setPacketFilters attaches the tailnet firewall rules using the field the
// client's capability version understands.
//
// Until ACL policy lands the tailnet is allow-all, which is what the official
// service does for a tailnet with no policy document.
func setPacketFilters(resp *tailcfg.MapResponse, capVer tailcfg.CapabilityVersion) {
	rules := slices.Clone(tailcfg.FilterAllowAll)

	if capVer >= packetFiltersCapVer {
		resp.PacketFilters = map[string][]tailcfg.FilterRule{"base": rules}
		return
	}
	resp.PacketFilter = rules
}

func boolPtr(b bool) *bool { return &b }
