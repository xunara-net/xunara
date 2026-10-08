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
	// Visibility lists the selectors (the ACL source-selector grammar) whose
	// nodes may discover this service through MagicDNS. It is normalized:
	// trimmed, deduplicated and sorted, with "*" meaning the whole
	// organization. An empty value means the default, "*": the v1 behavior.
	// Visibility narrows discovery only; the ACL rules still decide who may
	// connect.
	Visibility []string
	// Metadata is operator-facing description (version, region, ...). It is
	// never a secret and never written to the audit log.
	Metadata map[string]string
	// Created is when the node first published this name, Updated when it last
	// changed the record. A replace preserves Created for unchanged names.
	Created time.Time
	Updated time.Time

	// Health is true when the declaration enabled readiness reporting for
	// this service. Services without it are untracked: they are always
	// discoverable, exactly as before health reporting existed.
	Health bool
	// Healthy is the readiness the node last reported. It is only meaningful
	// when Health is set; the janitor clears it once the report's deadline
	// passes, so a stored true is never stale.
	Healthy bool
	// HealthReportedAt is when the node last reported this service's
	// readiness (explicitly ready/not ready, or implicitly by leaving it out
	// of a complete report). Zero when it never did.
	HealthReportedAt time.Time
	// HealthUntil is when the last report stops being valid. Zero when no
	// report is pending.
	HealthUntil time.Time
}

// ServiceHealth is a service's health as discovery surfaces apply it.
type ServiceHealth string

const (
	// ServiceHealthUntracked means the declaration did not enable health
	// reporting: the service is always discoverable.
	ServiceHealthUntracked ServiceHealth = "untracked"
	// ServiceHealthHealthy means the node reported the service ready and the
	// report has not expired.
	ServiceHealthHealthy ServiceHealth = "healthy"
	// ServiceHealthUnhealthy means the service was never reported ready, was
	// reported not ready, or its last report expired. Unhealthy services are
	// withdrawn from discovery (no MagicDNS record).
	ServiceHealthUnhealthy ServiceHealth = "unhealthy"
)

// EffectiveHealth classifies the service for discovery. Unhealthy services
// stay in listings (administrators must see them) but produce no DNS records.
func (s Service) EffectiveHealth() ServiceHealth {
	if !s.Health {
		return ServiceHealthUntracked
	}
	if s.Healthy {
		return ServiceHealthHealthy
	}
	return ServiceHealthUnhealthy
}

// ServiceHealthReport is one service's reported readiness.
type ServiceHealthReport struct {
	Name  string
	Ready bool
}

// Static reasons a health change carries into the audit log. They are fixed
// strings: peer-supplied text never reaches this path.
const (
	ServiceHealthReasonReported = "reported"
	ServiceHealthReasonExpired  = "report expired"
)

// ServiceHealthChange describes one service whose effective health changed.
// Only transitions are reported: a node repeating "ready" must not produce
// audit noise or wake netmap streams.
type ServiceHealthChange struct {
	NodeID   NodeID
	Name     string
	Protocol string
	Port     uint16
	Healthy  bool
	Reason   string
}

// ErrServiceNameTaken means another node already advertises this service name.
// Names are unique per organization, so a conflicting publish must fail rather
// than silently take the name over.
var ErrServiceNameTaken = errors.New("state: service name is already taken")

// ErrServiceHealthUnknown means a health report named a service the node does
// not advertise with health tracking enabled. Reports are fail-closed as a
// whole: a name the control plane cannot account for is a client bug.
var ErrServiceHealthUnknown = errors.New("state: service does not track health")

// errServiceHealthUnknown wraps [ErrServiceHealthUnknown] with the name.
func errServiceHealthUnknown(name string) error {
	return fmt.Errorf("%w: %q", ErrServiceHealthUnknown, name)
}

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
	// ReportServiceHealth replaces one node's complete readiness report for
	// its health-tracked services: named services take their reported
	// readiness, tracked services left out of the report are marked not
	// ready, and every report's deadline is now+ttl. It returns the services
	// whose effective health changed. It fails if the node is unknown, or
	// with [ErrServiceHealthUnknown] when a reported name is not advertised
	// with health tracking enabled.
	ReportServiceHealth(id NodeID, reports []ServiceHealthReport, ttl time.Duration) ([]ServiceHealthChange, error)
	// ExpireServiceHealth marks reports past their deadline as not ready and
	// returns the affected services. The janitor runs it; a stored
	// healthy=true is therefore never stale.
	ExpireServiceHealth(now time.Time) ([]ServiceHealthChange, error)
}
