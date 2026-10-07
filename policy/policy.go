// Package policy compiles a tailnet ACL document into the packet filter the
// control plane sends to clients (MapResponse.PacketFilters/PacketFilter).
//
// The wire types are tailscale.com/tailcfg; this package only decides what goes
// in them. It is deliberately pure — a parsed document plus node snapshots in,
// filter rules out — so the compiler can be tested without a server.
//
// Reference: reference/headscale/hscontrol/policy (document structure) and
// reference/tailscale/tailcfg/tailcfg.go (FilterRule semantics).
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Document is a tailnet ACL document: HuJSON with the fields Xunara understands.
type Document struct {
	// ACLs are the traffic rules.
	ACLs []ACLRow `json:"acls,omitempty"`

	// Grants are ACL v2 rules: like ACLs, but with protocol:port "ip"
	// entries and per-peer "app" capability grants.
	Grants []GrantRow `json:"grants,omitempty"`

	// Groups map "group:name" to its members (users, tags or other groups).
	Groups map[string][]string `json:"groups,omitempty"`

	// Hosts map aliases to IP addresses or prefixes.
	Hosts map[string]string `json:"hosts,omitempty"`

	// TagOwners map "tag:name" to the principals allowed to claim it. Xunara
	// validates the section but tag assignment itself lands with tagged auth
	// keys.
	TagOwners map[string][]string `json:"tagOwners,omitempty"`

	// SSH are the Tailscale SSH rules: which principals may open an SSH
	// session to which devices, as which local users.
	SSH []SSHRow `json:"ssh,omitempty"`

	// NodeAttrs grant extra capabilities to the nodes a target selector
	// names, for example "https" (enable HTTPS) or
	// "https://tailscale.com/cap/file-sharing".
	NodeAttrs []NodeAttrRow `json:"nodeAttrs,omitempty"`

	// Tests are assertions about the compiled policy, as in the official ACL
	// file format.
	Tests []Test `json:"tests,omitempty"`

	// Unsupported lists top-level fields present in the document that this
	// build does not implement (for example "grants" or "autoApprovers"). They are never
	// silently treated as granting access: a policy that relies on them denies
	// more than its author intended, and the server logs them at load time.
	Unsupported []string `json:"-"`
}

// NodeAttrRow is one rule of the document's "nodeAttrs" section.
type NodeAttrRow struct {
	// Target names the nodes the attrs apply to: a user, group, tag, host,
	// prefix, autogroup:member, autogroup:tagged or *.
	Target []string `json:"target,omitempty"`

	// Attr are the capability names granted to those nodes.
	Attr []string `json:"attr,omitempty"`
}

// SSHRow is one rule of the document's "ssh" section.
type SSHRow struct {
	// Action is "accept" (grant immediately) or "check" (ask the control
	// plane before each session, subject to CheckPeriod).
	Action string `json:"action"`

	// Src are the source selectors (users, groups, tags, hosts, prefixes).
	Src []string `json:"src,omitempty"`

	// Dst are the destination host selectors (no ports).
	Dst []string `json:"dst,omitempty"`

	// Users are the local users the session may run as: "root",
	// "autogroup:nonroot", or a plain user name.
	Users []string `json:"users,omitempty"`

	// AcceptEnv allowlists environment variables the client may forward.
	AcceptEnv []string `json:"acceptEnv,omitempty"`

	// CheckPeriod is how long an approved "check" session is remembered so
	// later sessions from the same device skip the prompt. Only valid with
	// action "check"; absent means the 12h default, "always" means every
	// session is checked.
	CheckPeriod *SSHCheckPeriod `json:"checkPeriod,omitempty"`
}

// SSHCheckPeriod is the value of an ssh rule's "checkPeriod" field.
type SSHCheckPeriod struct {
	// Always is set when the document wrote "always".
	Always bool

	// Duration is the period when Always is false.
	Duration time.Duration
}

// UnmarshalJSON parses "always" or a Go duration string such as "12h".
func (p *SSHCheckPeriod) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("checkPeriod must be a duration string or %q: %w", "always", err)
	}
	if strings.TrimSpace(s) == "always" {
		p.Always = true
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("checkPeriod %q: %w", s, err)
	}
	p.Duration = d
	return nil
}

// GrantRow is one rule of the document's "grants" section.
type GrantRow struct {
	// Src are the source selectors, as in an ACL.
	Src []string `json:"src,omitempty"`

	// Dst are the destination selectors; "autogroup:self" is resolved
	// relative to the node the filter is compiled for.
	Dst []string `json:"dst,omitempty"`

	// IP are "protocol:ports" entries ("tcp:443", "udp:6000-6100", "443",
	// or "*"). Every entry becomes a filter rule on its own.
	IP []string `json:"ip,omitempty"`

	// App maps a peer capability name to its JSON values; the capability is
	// delivered in the filter's CapGrant so the destination can decide what
	// the source may do.
	App map[string][]json.RawMessage `json:"app,omitempty"`

	// Via names the subnet routers the traffic must traverse. This build
	// does not implement via grants, so a non-empty list is rejected at
	// load time rather than silently widening access.
	Via []string `json:"via,omitempty"`
}

// ACLRow is one traffic rule.
type ACLRow struct {
	// Action is "accept" (the only supported action).
	Action string `json:"action,omitempty"`

	// Proto restricts the rule to one IP protocol name ("tcp", "udp", "icmp",
	// "icmpv6", ...) or number. Empty means the client's default set.
	Proto string `json:"proto,omitempty"`

	// Src are source selectors.
	Src []string `json:"src,omitempty"`

	// Dst are destination selectors of the form "host:port".
	Dst []string `json:"dst,omitempty"`

	// Users and Ports are the pre-v2 names of Src and Dst.
	Users []string `json:"users,omitempty"`
	Ports []string `json:"ports,omitempty"`
}

// Test asserts that traffic is or is not allowed by the policy.
type Test struct {
	Src    string   `json:"src,omitempty"`
	User   string   `json:"user,omitempty"`
	Proto  string   `json:"proto,omitempty"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`

	// Allow is the pre-v2 name of Accept.
	Allow []string `json:"allow,omitempty"`
}

// Parse reads an ACL document. It accepts HuJSON (JSON with comments and
// trailing commas), the format the official client and admin console use.
func Parse(raw []byte) (*Document, error) {
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("policy: parsing HuJSON: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(standard, &fields); err != nil {
		return nil, fmt.Errorf("policy: parsing document: %w", err)
	}

	doc := &Document{}
	targets := map[string]any{
		"acls":      &doc.ACLs,
		"groups":    &doc.Groups,
		"hosts":     &doc.Hosts,
		"tagOwners": &doc.TagOwners,
		"tests":     &doc.Tests,
		"ssh":       &doc.SSH,
		"nodeAttrs": &doc.NodeAttrs,
		"grants":    &doc.Grants,
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		target, ok := targets[key]
		if !ok {
			doc.Unsupported = append(doc.Unsupported, key)
			continue
		}
		if err := json.Unmarshal(fields[key], target); err != nil {
			return nil, fmt.Errorf("policy: parsing %q: %w", key, err)
		}
	}

	return doc, nil
}

// ParseString is Parse for a string document.
func ParseString(raw string) (*Document, error) { return Parse([]byte(raw)) }

// Load reads and parses an ACL document from disk.
func Load(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}
