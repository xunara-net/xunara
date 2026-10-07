package state

import "errors"

// errDNSRecordNameRequired is returned when a record is stored without a name.
var errDNSRecordNameRequired = errors.New("state: DNS record name is required")

// DNSRecordStore is the MagicDNS record half of the persistence boundary.
//
// Records are keyed by (name, type, value): storing the same ACME challenge
// twice is idempotent, while two different TXT values for the same name can
// coexist, as the DNS-01 protocol requires during a rollover.
type DNSRecordStore interface {
	// UpsertDNSRecord stores a record, assigning ID and Created on first
	// insert and reporting the existing identifier on a repeat.
	UpsertDNSRecord(r *DNSRecord) error
	// ListDNSRecords returns every record, oldest first.
	ListDNSRecords() []DNSRecord
	// DeleteDNSRecord removes a record by ID. It is a no-op if unknown.
	DeleteDNSRecord(id uint64) error
}
