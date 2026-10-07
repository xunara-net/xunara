package state

import (
	"fmt"
	"strings"
	"time"
)

// DNSRecord is a DNS record the control plane publishes to tailnet clients
// through MagicDNS (MapResponse.DNSConfig.ExtraRecords).
//
// Records are created by clients through /machine/set-dns to answer ACME
// DNS-01 challenges, and by administrators.
type DNSRecord struct {
	// ID is the server-local record identifier.
	ID uint64

	// Name is the record's owner, lowercased and without a trailing dot.
	Name string

	// Type is the DNS record type ("TXT", "A", ...).
	Type string

	// Value is the record's value, e.g. the TXT payload.
	Value string

	// NodeID is the node that asked for the record, or 0 for an
	// administrator-created one. It is provenance only, never authorization.
	NodeID NodeID

	// Created is when the record was first stored.
	Created time.Time
}

// NormalizeDNSRecordName lowercases a DNS name, strips the trailing dot and
// rejects anything that is not a valid DNS name.
//
// A "name" here is an owner name for a record, so a leading "_" label (as in
// "_acme-challenge.example.com") is allowed; the strict hostname rules for
// nodes do not apply.
func NormalizeDNSRecordName(name string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if trimmed == "" {
		return "", fmt.Errorf("state: empty DNS record name")
	}
	if !strings.Contains(trimmed, ".") {
		return "", fmt.Errorf("state: DNS record name %q must be fully qualified", name)
	}

	if len(trimmed) > maxDNSNameLength {
		return "", fmt.Errorf("state: DNS record name %q is longer than %d bytes", name, maxDNSNameLength)
	}

	for label := range strings.SplitSeq(trimmed, ".") {
		if !validRecordLabel(label) {
			return "", fmt.Errorf("state: invalid label %q in DNS record name %q", label, name)
		}
	}
	return trimmed, nil
}

// maxDNSNameLength is the wire limit for a DNS name in presentation format.
const maxDNSNameLength = 253

// validRecordLabel reports whether label is usable in a record owner name.
//
// It is deliberately looser than [dnsname.ValidLabel]: record owners routinely
// start with an underscore ("_acme-challenge"), which is not a valid hostname
// label but is exactly what certificate validation needs.
func validRecordLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		switch c := label[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// NormalizeDNSRecordType uppercases and validates a record type. An empty type
// is accepted and stored as "A", the tailcfg default for address records.
func NormalizeDNSRecordType(recordType string) (string, error) {
	t := strings.ToUpper(strings.TrimSpace(recordType))
	if t == "" {
		t = "A"
	}

	switch t {
	case "A", "AAAA", "TXT", "CNAME":
		return t, nil
	default:
		return "", fmt.Errorf("state: unsupported DNS record type %q", recordType)
	}
}

// FQDN returns the record name in absolute form.
func (r DNSRecord) FQDN() string { return r.Name + "." }
