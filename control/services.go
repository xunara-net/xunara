package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

// This file implements Xunara Atlas service discovery: the services a node
// advertises about itself over the native client protocol
// (POST /api/agent/v1/services).
//
// The official client protocol is untouched: an official client discovers a
// service through MagicDNS (the A/AAAA records this file feeds into the
// netmap) and connects to it under the existing ACL rules. Discovery is not
// authorization: publishing a name grants nothing, and the endpoints are
// never proxied by the control plane.
//
// The node is the only writer (the same boundary as device posture
// attributes): the platform surfaces are read-only, so a compromised admin
// credential cannot make a node look like it hosts a service it does not.

const (
	// maxServicesPerNode bounds how many services one node may advertise.
	maxServicesPerNode = 32
	// maxServicesPerOrg bounds the whole registry. Every service becomes
	// MagicDNS records on every netmap, so the registry is bounded in the
	// organization, not only per node.
	maxServicesPerOrg = 512
	// maxServiceNameLen bounds a service name. Names are DNS labels: they
	// become <name>.<domain> in MagicDNS.
	maxServiceNameLen = 63
	// maxServiceMetadataEntries bounds one service's metadata map.
	maxServiceMetadataEntries = 16
	// maxServiceMetadataKeyLen bounds a metadata key (same shape as device
	// attribute names: printable ASCII without spaces).
	maxServiceMetadataKeyLen = 64
	// maxServiceMetadataValueLen bounds a metadata value.
	maxServiceMetadataValueLen = 256
	// maxServiceMetadataBytes bounds the encoded metadata of one service.
	maxServiceMetadataBytes = 2 << 10
)

// agentServicesRequest is the body of POST /api/agent/v1/services. The list is
// the node's complete set: names left out are withdrawn.
type agentServicesRequest struct {
	agentRequest
	Services []agentService `json:"services"`
}

// agentService is one advertised service as the client sends it.
type agentService struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Port     uint32            `json:"port"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// serviceView is the JSON shape of a stored service on every read surface.
type serviceView struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Port     uint16            `json:"port"`
	Metadata map[string]string `json:"metadata,omitempty"`
	NodeID   uint64            `json:"nodeId"`
	StableID string            `json:"stableId"`
	Hostname string            `json:"hostname"`
	// DNSName is the MagicDNS name the service is reachable under, when the
	// deployment has a domain configured.
	DNSName string `json:"dnsName,omitempty"`
	// Created and Updated mirror the store's bookkeeping.
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// agentServicesResponse is the answer to a publish: the stored set.
type agentServicesResponse struct {
	Services []serviceView `json:"services"`
}

// handleAgentServices implements POST /api/agent/v1/services: a node replaces
// the set of services it advertises.
func (s *Server) handleAgentServices(w http.ResponseWriter, req *http.Request) {
	var body agentServicesRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	node, _, err := s.authenticateAgent(req, body.agentRequest)
	if err != nil {
		httpError(w, err)
		return
	}

	services, err := normalizeAgentServices(body.Services)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	// A node's declaration is reconciled: an agent may re-publish it on a
	// timer to repair a control plane that lost the record. A publish that
	// already matches the store is therefore in effect and must not rewrite
	// rows, append an audit event or wake every netmap stream; everything
	// below this point is a real change.
	current, err := s.store.ServicesForNode(node.ID)
	if err != nil {
		s.log.Error("reading services", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if sameServiceSet(current, services) {
		writeJSON(w, http.StatusOK, agentServicesResponse{Services: s.serviceViews(node, current)})
		return
	}

	if err := s.checkServiceNameConflicts(node, services); err != nil {
		httpError(w, NewHTTPError(http.StatusConflict, err.Error(), nil))
		return
	}
	if err := s.checkServiceBudget(node, services); err != nil {
		httpError(w, NewHTTPError(http.StatusTooManyRequests, err.Error(), nil))
		return
	}

	if err := s.store.ReplaceNodeServices(node.ID, services); err != nil {
		if errors.Is(err, state.ErrServiceNameTaken) {
			// Another node claimed the name between the conflict check and the
			// write, or the store holds a name this instance did not see.
			httpError(w, NewHTTPError(http.StatusConflict, "a service name is already in use", nil))
			return
		}
		s.log.Error("storing services", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	s.audit(nodeActor(node), identity.AuditServicesUpdated, nodeTarget(node), servicesAuditDetail(services))
	// The service's MagicDNS records changed, so streaming sessions have a new
	// netmap to send.
	s.notifyWatchers()

	stored, err := s.store.ServicesForNode(node.ID)
	if err != nil {
		s.log.Error("reading back services", "node", node.StableID, "err", err)
		stored = services
	}
	writeJSON(w, http.StatusOK, agentServicesResponse{Services: s.serviceViews(node, stored)})
}

// serviceViews renders a stored set for a response.
func (s *Server) serviceViews(node state.Node, services []state.Service) []serviceView {
	views := make([]serviceView, 0, len(services))
	for _, svc := range services {
		views = append(views, s.serviceView(svc, node))
	}
	return views
}

// sameServiceSet reports whether a declaration matches the stored set. A
// declaration is a set, not a list: order carries no meaning. Names are unique
// on both sides (the store enforces it, normalizeAgentServices enforces it),
// so comparing by name is unambiguous.
func sameServiceSet(stored, declared []state.Service) bool {
	if len(stored) != len(declared) {
		return false
	}
	byName := make(map[string]state.Service, len(stored))
	for _, svc := range stored {
		byName[svc.Name] = svc
	}
	for _, svc := range declared {
		other, ok := byName[svc.Name]
		if !ok {
			return false
		}
		if svc.Protocol != other.Protocol || svc.Port != other.Port {
			return false
		}
		if !maps.Equal(svc.Metadata, other.Metadata) {
			return false
		}
	}
	return true
}

// normalizeAgentServices validates a published set and converts it to store
// records. Every rule is fail-closed: the whole publish fails rather than
// dropping or rewriting a service the node meant to advertise.
func normalizeAgentServices(services []agentService) ([]state.Service, error) {
	if len(services) > maxServicesPerNode {
		return nil, fmt.Errorf("at most %d services may be advertised per node", maxServicesPerNode)
	}

	out := make([]state.Service, 0, len(services))
	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if err := validateServiceName(svc.Name); err != nil {
			return nil, err
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("service name %q is listed twice", svc.Name)
		}
		seen[svc.Name] = true

		protocol := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if protocol != "tcp" && protocol != "udp" {
			return nil, fmt.Errorf("service %q has an unsupported protocol %q", svc.Name, svc.Protocol)
		}
		if svc.Port == 0 || svc.Port > 65535 {
			return nil, fmt.Errorf("service %q has an invalid port", svc.Name)
		}
		metadata, err := validateServiceMetadata(svc.Metadata)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}

		out = append(out, state.Service{
			Name:     svc.Name,
			Protocol: protocol,
			Port:     uint16(svc.Port),
			Metadata: metadata,
		})
	}
	return out, nil
}

// validateServiceName enforces the DNS label shape a service name must have.
// The name becomes a DNS name (<name>.<domain>), so anything that could not be
// resolved — uppercase, underscores, a leading digit-free label — is refused
// rather than silently sanitized into a different name.
func validateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name is empty")
	}
	if len(name) > maxServiceNameLen {
		return fmt.Errorf("service name is longer than %d bytes", maxServiceNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return fmt.Errorf("service name %q must not start or end with a hyphen", name)
			}
		default:
			return fmt.Errorf("service name %q must be a lowercase DNS label", name)
		}
	}
	return nil
}

// validateServiceMetadata bounds and cleans one service's metadata. Keys and
// values are printable (no control characters), so the console and terminal
// surfaces cannot be made to render escape sequences.
func validateServiceMetadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	if len(metadata) > maxServiceMetadataEntries {
		return nil, fmt.Errorf("metadata has more than %d entries", maxServiceMetadataEntries)
	}

	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if key == "" || len(key) > maxServiceMetadataKeyLen || !printableASCII(key, false) {
			return nil, fmt.Errorf("metadata key %q is invalid", sanitizeServiceName(key))
		}
		if len(value) > maxServiceMetadataValueLen || !printableASCII(value, true) {
			return nil, fmt.Errorf("metadata value of %q is invalid", sanitizeServiceName(key))
		}
		out[key] = value
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("metadata cannot be encoded")
	}
	if len(encoded) > maxServiceMetadataBytes {
		return nil, fmt.Errorf("metadata is larger than %d bytes", maxServiceMetadataBytes)
	}
	return out, nil
}

// printableASCII reports whether s is printable ASCII. Space is only allowed
// when allowSpace is set (values may read as prose; keys may not).
func printableASCII(s string, allowSpace bool) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		if allowSpace && r == ' ' {
			continue
		}
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// sanitizeServiceName makes an untrusted name safe to echo back in an error
// message: printable ASCII only, bounded.
func sanitizeServiceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > unicode.MaxASCII || (r < 0x21 && r != ' ') || r == 0x7f {
			continue
		}
		if b.Len() >= 64 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// checkServiceNameConflicts rejects names that would collide with an existing
// MagicDNS name: a node's own FQDN or any record already published. Names of
// other nodes' services are checked again by the store when it writes, because
// that check has to be atomic with the replacement.
func (s *Server) checkServiceNameConflicts(node state.Node, services []state.Service) error {
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		// Without a MagicDNS domain there are no names to collide with, and
		// the store still guarantees uniqueness among services.
		return nil
	}

	for _, n := range s.store.ListNodes() {
		// The publishing node is included: a service named after its own
		// hostname would shadow (or duplicate) the node's MagicDNS name, and
		// the node can pick another name at no cost.
		fqdn := strings.TrimSuffix(n.FQDN(domain), ".")
		for _, svc := range services {
			if svc.Name == strings.SplitN(fqdn, ".", 2)[0] {
				return fmt.Errorf("service name %q is already the hostname of node %s", svc.Name, n.StableID)
			}
		}
	}

	records := s.store.ListDNSRecords()
	for _, svc := range services {
		want := svc.Name + "." + domain
		for _, rec := range records {
			if strings.EqualFold(strings.TrimSuffix(rec.Name, "."), want) {
				return fmt.Errorf("service name %q is already a DNS record", svc.Name)
			}
		}
	}
	return nil
}

// checkServiceBudget bounds the organization's registry. The node's own
// current services are replaced, so only other nodes' entries and the new set
// count towards the limit.
func (s *Server) checkServiceBudget(node state.Node, services []state.Service) error {
	counts, err := s.store.NodeServiceCounts()
	if err != nil {
		return fmt.Errorf("counting services: %w", err)
	}
	other := 0
	for id, count := range counts {
		if id != node.ID {
			other += count
		}
	}
	if other+len(services) > maxServicesPerOrg {
		return fmt.Errorf("service limit (%d) reached", maxServicesPerOrg)
	}
	return nil
}

// serviceView renders one stored service for the read surfaces.
func (s *Server) serviceView(svc state.Service, node state.Node) serviceView {
	view := serviceView{
		Name:     svc.Name,
		Protocol: svc.Protocol,
		Port:     svc.Port,
		Metadata: svc.Metadata,
		NodeID:   uint64(node.ID),
		StableID: node.StableID,
		Hostname: node.Hostname,
		Created:  svc.Created,
		Updated:  svc.Updated,
	}
	if domain := strings.Trim(s.cfg.Domain, "."); domain != "" {
		view.DNSName = svc.Name + "." + domain
	}
	return view
}

// servicesAuditDetail describes a publish for the audit log: which services
// are advertised, never their metadata (AGENTS.md section 8: metadata can
// carry identifiers, and the audit log is exported to webhooks).
func servicesAuditDetail(services []state.Service) string {
	if len(services) == 0 {
		return "withdrew all services"
	}
	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, fmt.Sprintf("%s/%s:%d", svc.Name, svc.Protocol, svc.Port))
	}
	sort.Strings(names)
	return truncateClean("advertised "+strings.Join(names, ", "), maxAuditDetailsLen)
}

// serviceDNSRecords renders advertised services as MagicDNS A/AAAA records
// pointing at the node that advertises them. Discovery through DNS is what
// makes a service usable by an official client, which resolves the name and
// connects under the existing ACL rules.
func (s *Server) serviceDNSRecords() []state.DNSRecord {
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		return nil
	}

	var out []state.DNSRecord
	for _, svc := range s.store.ListServices() {
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			// The node was deleted; the store cascade already dropped the
			// service, so this is a stale read.
			continue
		}
		name := svc.Name + "." + domain
		if node.IPv4.IsValid() {
			out = append(out, state.DNSRecord{Name: name, Type: "A", Value: node.IPv4.String(), NodeID: node.ID})
		}
		if node.IPv6.IsValid() {
			out = append(out, state.DNSRecord{Name: name, Type: "AAAA", Value: node.IPv6.String(), NodeID: node.ID})
		}
	}
	return out
}
