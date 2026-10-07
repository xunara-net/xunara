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
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"

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

	// Resolvers are the tailnet's global DNS resolvers, in preference order.
	Resolvers []*dnstype.Resolver

	// Routes is the split-DNS table: DNS suffix to the resolvers that answer
	// it.
	Routes map[string][]*dnstype.Resolver

	// ExtraRecords are administrator- and ACME-created records published to
	// every client through MagicDNS.
	ExtraRecords []state.DNSRecord

	// UserProfile describes a user to clients. A nil function falls back to the
	// single-user default profile.
	UserProfile func(id tailcfg.UserID) tailcfg.UserProfile

	// FilterFor returns the packet filter a node should receive. A nil
	// function means the tailnet has no policy document, which allows
	// everything (the official default for a tailnet without a policy).
	//
	// The returned slice may be empty, which means "block everything": an
	// empty rule set is a meaningful policy, not a missing one.
	FilterFor func(self state.Node) []tailcfg.FilterRule

	// SSHPolicyFor returns the SSH policy a node receives as the destination
	// of incoming SSH connections, or nil when no SSH rule applies to it.
	SSHPolicyFor func(self state.Node) *tailcfg.SSHPolicy

	// SSHDestination reports whether a node is named as an SSH destination by
	// the policy. Such nodes advertise the tailscale.com/cap/ssh capability,
	// which is what allows them to run the Tailscale SSH server.
	SSHDestination func(state.Node) bool

	// DERPMap is advertised to clients when non-nil.
	DERPMap *tailcfg.DERPMap
}

// Full builds the first MapResponse of a session: everything a client needs to
// construct its netmap.
//
// nodes must include the requesting node; it is filtered out of Peers.
func Full(self state.Node, nodes []state.Node, cfg Config, online OnlineFunc, capVer tailcfg.CapabilityVersion) *tailcfg.MapResponse {
	routes := NewRouteTable(nodes)
	resp := &tailcfg.MapResponse{
		Node:         Node(self, true, online, routes, cfg),
		Peers:        peerNodes(self, nodes, online, routes, cfg),
		Domain:       cfg.Domain,
		DNSConfig:    DNSConfig(cfg),
		DERPMap:      cfg.DERPMap,
		UserProfiles: userProfiles(self, nodes, cfg),
		SSHPolicy:    sshPolicyFor(cfg, self),
	}
	SetPacketFilters(resp, capVer, packetFilterFor(cfg, self))
	return resp
}

// Update builds a MapResponse for a netmap change.
//
// Only fields that can change are set: nil means "unchanged" on the client, so
// DNSConfig, DERPMap, Domain and the packet filter are left alone.
func Update(self state.Node, nodes []state.Node, cfg Config, online OnlineFunc) *tailcfg.MapResponse {
	routes := NewRouteTable(nodes)
	return &tailcfg.MapResponse{
		Node:         Node(self, true, online, routes, cfg),
		Peers:        peerNodes(self, nodes, online, routes, cfg),
		UserProfiles: userProfiles(self, nodes, cfg),
		SSHPolicy:    sshPolicyFor(cfg, self),
	}
}

// sshPolicyFor builds a node's SSH policy, tolerating a nil hook.
func sshPolicyFor(cfg Config, self state.Node) *tailcfg.SSHPolicy {
	if cfg.SSHPolicyFor == nil {
		return nil
	}
	return cfg.SSHPolicyFor(self)
}

// RouteTable maps a served route prefix to the node elected to serve it.
//
// A route can be advertised by more than one node. The tailnet serves it
// through exactly one of them ("primary"), chosen deterministically as the
// lowest node ID so that every mapper instance in a cluster agrees. This is
// what upstream calls the primary route election; without it two routers would
// both claim the prefix and traffic would flap.
type RouteTable map[netip.Prefix]state.NodeID

// NewRouteTable elects a primary node for every effectively served route among
// nodes.
func NewRouteTable(nodes []state.Node) RouteTable {
	table := make(RouteTable)
	for _, n := range nodes {
		for _, r := range n.EffectiveRoutes() {
			if id, ok := table[r]; !ok || n.ID < id {
				table[r] = n.ID
			}
		}
	}
	return table
}

// Node converts a stored node into its wire representation.
//
// AllowedIPs carries the node's own addresses plus the routes it serves (the
// approved subset of what it advertises, minus prefixes another node is the
// elected primary for). PrimaryRoutes carries the served subnet routes only:
// exit routes reach the client through AllowedIPs and must not appear there,
// matching upstream.
func Node(n state.Node, self bool, online OnlineFunc, routes RouteTable, cfg Config) *tailcfg.Node {
	addresses := make([]netip.Prefix, 0, 2)
	if n.IPv4.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv4, n.IPv4.BitLen()))
	}
	if n.IPv6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv6, n.IPv6.BitLen()))
	}

	allowed := slices.Clone(addresses)
	var primary []netip.Prefix
	for _, r := range n.EffectiveRoutes() {
		if id, ok := routes[r]; ok && id != n.ID {
			continue
		}
		allowed = append(allowed, r)
		if !state.IsExitRoute(r) {
			primary = append(primary, r)
		}
	}
	slices.SortFunc(allowed, netip.Prefix.Compare)

	out := &tailcfg.Node{
		ID:            tailcfg.NodeID(n.ID),
		StableID:      tailcfg.StableNodeID(n.StableID),
		Name:          n.FQDN(cfg.Domain),
		User:          n.UserID,
		Key:           n.NodeKey,
		KeyExpiry:     n.Expiry,
		Expired:       n.Expired(time.Now()),
		Machine:       n.MachineKey,
		DiscoKey:      n.DiscoKey,
		Addresses:     addresses,
		AllowedIPs:    allowed,
		PrimaryRoutes: primary,
		Endpoints:     slices.Clone(n.Endpoints),
		HomeDERP:      n.HomeDERP,
		Created:       n.Created,
		Cap:           n.CapVer,
		LastSeen:      n.LastSeen,
		Tags:          slices.Clone(n.Tags),
	}

	if n.Hostinfo != nil {
		out.Hostinfo = n.Hostinfo.View()
	}

	// A node that the SSH policy names as a destination advertises the
	// capability that lets it run the Tailscale SSH server.
	if cfg.SSHDestination != nil && cfg.SSHDestination(n) {
		out.CapMap = tailcfg.NodeCapMap{tailcfg.CapabilitySSH: nil}
	}

	// The requesting node is online by construction; peers are online when they
	// hold a live control session.
	out.Online = boolPtr(self || online(n.ID))

	return out
}

// peerNodes converts every node except self, sorted by ID as the wire requires.
func peerNodes(self state.Node, nodes []state.Node, online OnlineFunc, routes RouteTable, cfg Config) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		out = append(out, Node(n, false, online, routes, cfg))
	}
	slices.SortFunc(out, func(a, b *tailcfg.Node) int {
		return int(a.ID) - int(b.ID)
	})
	return out
}

// userProfiles builds the profiles for the requesting node and its peers,
// sorted by user ID as the wire requires.
func userProfiles(self state.Node, nodes []state.Node, cfg Config) []tailcfg.UserProfile {
	seen := make(map[tailcfg.UserID]bool)
	out := make([]tailcfg.UserProfile, 0, len(nodes)+1)

	profile := cfg.UserProfile
	if profile == nil {
		profile = state.DefaultUserProfile
	}

	add := func(id tailcfg.UserID) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, profile(id))
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

// DNSConfig builds the MagicDNS configuration, or nil when the tailnet has no
// domain configured (nil means "unchanged"/"none" to the client).
//
// CertDomains advertises that this control plane answers ACME DNS-01
// challenges for the tailnet's MagicDNS suffix: a client that runs "tailscale
// cert" POSTs the challenge record to /machine/set-dns, and the record is then
// served to the tailnet through ExtraRecords.
func DNSConfig(cfg Config) *tailcfg.DNSConfig {
	domain := strings.Trim(cfg.Domain, ".")
	if domain == "" {
		return nil
	}

	out := &tailcfg.DNSConfig{
		Domains:     []string{domain},
		Proxied:     true,
		Resolvers:   cfg.Resolvers,
		Routes:      cfg.Routes,
		CertDomains: []string{domain},
	}
	for _, r := range cfg.ExtraRecords {
		out.ExtraRecords = append(out.ExtraRecords, tailcfg.DNSRecord{
			Name:  r.FQDN(),
			Type:  r.Type,
			Value: r.Value,
		})
	}
	return out
}

// packetFilterFor returns the rules a node receives, defaulting to allow-all
// when the tailnet has no policy document.
//
// The result is always non-nil so that an empty policy is sent as "no rules"
// rather than "no change".
func packetFilterFor(cfg Config, self state.Node) []tailcfg.FilterRule {
	if cfg.FilterFor == nil {
		return slices.Clone(tailcfg.FilterAllowAll)
	}
	rules := cfg.FilterFor(self)
	if rules == nil {
		return []tailcfg.FilterRule{}
	}
	return rules
}

// SetPacketFilters attaches packet filter rules to a response using the field
// the client's capability version understands.
//
// rules must be non-nil: an empty non-nil slice means "block everything",
// while a nil slice would mean "no change" in an update frame.
func SetPacketFilters(resp *tailcfg.MapResponse, capVer tailcfg.CapabilityVersion, rules []tailcfg.FilterRule) {
	if capVer >= packetFiltersCapVer {
		resp.PacketFilters = map[string][]tailcfg.FilterRule{"base": rules}
		return
	}
	resp.PacketFilter = rules
}

func boolPtr(b bool) *bool { return &b }
