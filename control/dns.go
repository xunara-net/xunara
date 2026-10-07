package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

// parseResolvers turns configured resolver strings into wire resolvers.
//
// An entry is either an IP address or "IP:port"; the default port (53) is left
// implicit so that clients apply their own defaults.
func parseResolvers(entries []string) ([]*dnstype.Resolver, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	out := make([]*dnstype.Resolver, 0, len(entries))
	for _, entry := range entries {
		addr, err := parseResolverAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("control: nameserver %q: %w", entry, err)
		}
		out = append(out, &dnstype.Resolver{Addr: addr})
	}
	return out, nil
}

func parseResolverAddr(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", fmt.Errorf("empty resolver")
	}

	if ap, err := netip.ParseAddrPort(entry); err == nil {
		return ap.String(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return "", fmt.Errorf("not an IP address or IP:port")
	}
	return addr.String(), nil
}

// parseDNSRoutes validates the split-DNS table.
func parseDNSRoutes(routes map[string][]string) (map[string][]*dnstype.Resolver, error) {
	if len(routes) == 0 {
		return nil, nil
	}

	out := make(map[string][]*dnstype.Resolver, len(routes))
	for suffix, entries := range routes {
		suffix, err := state.NormalizeDNSRecordName(suffix)
		if err != nil {
			return nil, fmt.Errorf("control: DNS route %q: %w", suffix, err)
		}
		resolvers, err := parseResolvers(entries)
		if err != nil {
			return nil, fmt.Errorf("control: DNS route %q: %w", suffix, err)
		}
		if len(resolvers) == 0 {
			// An empty resolver list means "handle this suffix with
			// MagicDNS"; that is meaningful, so keep it.
			out[suffix] = nil
			continue
		}
		out[suffix] = resolvers
	}
	return out, nil
}

// handleSetDNS implements POST /machine/set-dns inside a Noise session.
//
// Clients use it to answer ACME DNS-01 challenges for names under the
// tailnet's MagicDNS domain. Xunara stores the record durably and publishes it
// to every client through MapResponse.DNSConfig.ExtraRecords; it does not talk
// to an external DNS provider.
func (ns *noiseServer) handleSetDNS(w http.ResponseWriter, req *http.Request) {
	var setReq tailcfg.SetDNSRequest
	if err := json.NewDecoder(req.Body).Decode(&setReq); err != nil {
		httpError(w, err)
		return
	}

	if ns.rejectUnsupported(w, setReq.Version, setReq.NodeKey) {
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{
		NodeKey: setReq.NodeKey,
	})
	if err != nil {
		httpError(w, err)
		return
	}

	record, err := ns.server.dnsRecordFromRequest(node, setReq)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))
		return
	}
	if err := ns.server.checkDNSRecordBudget(record); err != nil {
		httpError(w, NewHTTPError(http.StatusTooManyRequests, err.Error(), err))
		return
	}
	if err := ns.server.store.UpsertDNSRecord(record); err != nil {
		httpError(w, err)
		return
	}

	ns.server.log.Info("stored DNS record",
		"node_id", int(node.ID),
		"name", record.Name,
		"type", record.Type,
		"record_id", record.ID)

	// The record value is not copied into the audit log: a TXT record may
	// carry an ACME challenge secret.
	ns.server.audit(nodeActor(node), identity.AuditDNSRecordSet,
		fmt.Sprintf("dns:%s/%s", record.Name, record.Type),
		fmt.Sprintf("published record %d", record.ID))

	// The new record has to reach every connected client, not just this one.
	ns.server.notifyWatchers()

	writeJSON(w, http.StatusOK, tailcfg.SetDNSResponse{})
}

// dnsRecordFromRequest validates a client's record request against the
// tailnet's MagicDNS domain and converts it to a stored record.
func (s *Server) dnsRecordFromRequest(node state.Node, req tailcfg.SetDNSRequest) (*state.DNSRecord, error) {
	name, err := state.NormalizeDNSRecordName(req.Name)
	if err != nil {
		return nil, err
	}
	recordType, err := state.NormalizeDNSRecordType(req.Type)
	if err != nil {
		return nil, err
	}
	if len(req.Value) > maxDNSRecordValueLength {
		return nil, fmt.Errorf("control: DNS record value is longer than %d bytes", maxDNSRecordValueLength)
	}

	// Only names under the tailnet's own MagicDNS suffix may be published:
	// otherwise any node could inject records for arbitrary domains into every
	// client's resolver.
	if err := s.checkRecordNameInDomain(name); err != nil {
		return nil, err
	}

	return &state.DNSRecord{
		Name:   name,
		Type:   recordType,
		Value:  req.Value,
		NodeID: node.ID,
	}, nil
}

// maxDNSRecordValueLength bounds a stored record value. ACME DNS-01 challenge
// values are 43 characters; the limit leaves room for other record types while
// keeping one node from filling the database.
const maxDNSRecordValueLength = 4096

// checkRecordNameInDomain reports whether name lives under the tailnet's
// MagicDNS domain.
func (s *Server) checkRecordNameInDomain(name string) error {
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		return fmt.Errorf("control: this tailnet has no MagicDNS domain configured")
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return fmt.Errorf("control: record name %q is outside the tailnet domain %q", name, domain)
	}
	return nil
}

// maxDNSRecords bounds how many records the control plane will publish, so a
// single misbehaving client cannot make every netmap unbounded.
const maxDNSRecords = 512

// checkDNSRecordBudget reports whether another record may be published. Repeats
// of an existing record are always allowed: they cost no extra space.
func (s *Server) checkDNSRecordBudget(record *state.DNSRecord) error {
	for _, existing := range s.store.ListDNSRecords() {
		if existing.Name == record.Name && existing.Type == record.Type && existing.Value == record.Value {
			return nil
		}
	}
	if got := len(s.store.ListDNSRecords()); got >= maxDNSRecords {
		return fmt.Errorf("control: DNS record limit (%d) reached", maxDNSRecords)
	}
	return nil
}
