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

	"github.com/tailscale/hujson"
)

// Document is a tailnet ACL document: HuJSON with the fields Xunara understands.
type Document struct {
	// ACLs are the traffic rules.
	ACLs []ACLRow `json:"acls,omitempty"`

	// Groups map "group:name" to its members (users, tags or other groups).
	Groups map[string][]string `json:"groups,omitempty"`

	// Hosts map aliases to IP addresses or prefixes.
	Hosts map[string]string `json:"hosts,omitempty"`

	// TagOwners map "tag:name" to the principals allowed to claim it. Xunara
	// validates the section but tag assignment itself lands with tagged auth
	// keys.
	TagOwners map[string][]string `json:"tagOwners,omitempty"`

	// Tests are assertions about the compiled policy, as in the official ACL
	// file format.
	Tests []Test `json:"tests,omitempty"`

	// Unsupported lists top-level fields present in the document that this
	// build does not implement (for example "ssh" or "grants"). They are never
	// silently treated as granting access: a policy that relies on them denies
	// more than its author intended, and the server logs them at load time.
	Unsupported []string `json:"-"`
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
