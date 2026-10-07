package state

import (
	"errors"
	"fmt"
	"time"
)

// Service is a network endpoint a node advertises about itself (Xunara Atlas
// service discovery, see the service-discovery section of the project spec).
//
// A service is owned by exactly one node: the name, protocol and port are the
// node's own claim, and only the node's credential can change or drop them
// (the platform surfaces are read-only). The control plane never probes the
// endpoint, so a published service is an advertisement, not an observation.
type Service struct {
	// NodeID is the node that advertises the service.
	NodeID NodeID
	// Name is the DNS label the service is published under. It is unique
	// inside one organization, so it can be resolved without ambiguity.
	Name string
	// Protocol is "tcp" or "udp".
	Protocol string
	// Port is the endpoint's port.
	Port uint16
	// Metadata is operator-facing description (version, region, ...). It is
	// never a secret and never written to the audit log.
	Metadata map[string]string
	// Created is when the node first published this name, Updated when it last
	// changed the record. A replace preserves Created for unchanged names.
	Created time.Time
	Updated time.Time
}

// ErrServiceNameTaken means another node already advertises this service name.
// Names are unique per organization, so a conflicting publish must fail rather
// than silently take the name over.
var ErrServiceNameTaken = errors.New("state: service name is already taken")

// errServiceNameTaken wraps [ErrServiceNameTaken] with the offending name.
func errServiceNameTaken(name string) error {
	return fmt.Errorf("%w: %q", ErrServiceNameTaken, name)
}

// errUnknownNode reports a node ID no node was created under.
func errUnknownNode(id NodeID) error {
	return fmt.Errorf("state: node %d is unknown", id)
}

// ServiceStore stores the services nodes advertise about themselves.
//
// Publishing is declarative: a node replaces its complete set in one call, so
// a partial failure can never leave a node advertising half a set.
type ServiceStore interface {
	// ReplaceNodeServices makes services the node's complete published set:
	// names not in the slice are removed, names already present keep their
	// creation time. The whole call is atomic. It fails if the node is
	// unknown, or with [ErrServiceNameTaken] when a name belongs to a
	// different node.
	ReplaceNodeServices(id NodeID, services []Service) error
	// ListServices returns every advertised service, ordered by name.
	ListServices() []Service
	// ServicesForNode returns one node's services, ordered by name.
	ServicesForNode(id NodeID) ([]Service, error)
	// GetServiceByName returns the service advertised under name.
	GetServiceByName(name string) (Service, bool)
	// NodeServiceCounts returns how many services each node advertises, for
	// list views that must not carry every record.
	NodeServiceCounts() (map[NodeID]int, error)
}
