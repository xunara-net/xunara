package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func newDNSAuthServer(t *testing.T) *Server {
	t.Helper()

	return newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		Nameservers: []string{"9.9.9.9", "1.1.1.1:5353"},
		DNSRoutes:   map[string][]string{"corp.xunara.test": {"10.0.0.53"}},
	})
}

// TestNetmapCarriesMagicDNSConfig checks the DNS half of the first netmap.
func TestNetmapCarriesMagicDNSConfig(t *testing.T) {
	s := newDNSAuthServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	if got := msg.Node.Name; got != "node-a.xunara.test." {
		t.Errorf("self name = %q, want node-a.xunara.test.", got)
	}

	dns := msg.DNSConfig
	if dns == nil {
		t.Fatal("map response has no DNSConfig")
	}
	if len(dns.Domains) != 1 || dns.Domains[0] != "xunara.test" {
		t.Errorf("Domains = %v, want [xunara.test]", dns.Domains)
	}
	if !dns.Proxied {
		t.Error("Proxied = false, want true")
	}
	if len(dns.Resolvers) != 2 || dns.Resolvers[0].Addr != "9.9.9.9" || dns.Resolvers[1].Addr != "1.1.1.1:5353" {
		t.Errorf("Resolvers = %v", dns.Resolvers)
	}
	if got := dns.Routes["corp.xunara.test"]; len(got) != 1 || got[0].Addr != "10.0.0.53" {
		t.Errorf("Routes = %v", dns.Routes)
	}
	// Without a public DNS provider the tailnet must not offer certificates:
	// a challenge could never be validated.
	if len(dns.CertDomains) != 0 {
		t.Errorf("CertDomains = %v, want none without a DNS provider", dns.CertDomains)
	}
	if msg.Domain != "xunara.test" {
		t.Errorf("Domain = %q, want xunara.test", msg.Domain)
	}
}

// TestSetDNSPublishesRecordToTailnet drives the ordinary-record path end to
// end: a client publishes a record, and every client's MagicDNS picks it up.
func TestSetDNSPublishesRecordToTailnet(t *testing.T) {
	s := newDNSAuthServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	sess := openMapSession(t, client, nodeKey.Public())
	defer sess.Body.Close()

	frames := mapFrames(sess.Body)
	view := newNetmapView()

	first := waitForNetmapFrame(t, frames, view, func(v *netmapView) bool { return v.self != nil })
	if first.DNSConfig == nil {
		t.Fatal("the first frame must carry the DNS configuration")
	}
	if len(first.DNSConfig.ExtraRecords) != 0 {
		t.Fatalf("ExtraRecords = %v, want none before any record is set", first.DNSConfig.ExtraRecords)
	}

	postRaw(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "notes.node-a.xunara.test.",
		Type:    "TXT",
		Value:   "hello",
	})

	update := waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	if update.DNSConfig == nil {
		t.Fatal("the update triggered by set-dns must carry the new DNS configuration")
	}
	if len(update.DNSConfig.ExtraRecords) != 1 {
		t.Fatalf("ExtraRecords = %v, want the new record", update.DNSConfig.ExtraRecords)
	}
	rec := update.DNSConfig.ExtraRecords[0]
	if rec.Name != "notes.node-a.xunara.test." || rec.Type != "TXT" || rec.Value != "hello" {
		t.Errorf("record = %+v", rec)
	}

	stored := s.Store().ListDNSRecords()
	if len(stored) != 1 {
		t.Fatalf("stored records = %v, want 1", stored)
	}
	if stored[0].NodeID == 0 {
		t.Error("stored record has no originating node")
	}

	// Republishing the same record is idempotent.
	postRaw(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "notes.node-a.xunara.test",
		Type:    "TXT",
		Value:   "hello",
	})
	if got := len(s.Store().ListDNSRecords()); got != 1 {
		t.Errorf("stored records after repeat = %d, want 1", got)
	}
}

// TestSetDNSRejectsOutsideDomain checks that a node cannot publish records for
// domains this control plane does not own.
func TestSetDNSRejectsOutsideDomain(t *testing.T) {
	s := newDNSAuthServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	for _, name := range []string{
		"_acme-challenge.evil.example.",
		"xunara.test.evil.example.",
		"not-a-fqdn",
	} {
		_, status := postRawStatus(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: nodeKey.Public(),
			Name:    name,
			Type:    "TXT",
			Value:   "token",
		})
		if status != http.StatusBadRequest {
			t.Errorf("set-dns %q status = %d, want 400", name, status)
		}
	}

	if got := len(s.Store().ListDNSRecords()); got != 0 {
		t.Errorf("stored records = %d, want 0", got)
	}
}

// TestSetDNSRequiresAConfiguredDomain checks the endpoint's behaviour on a
// tailnet without MagicDNS.
func TestSetDNSRequiresAConfiguredDomain(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	_, status := postRawStatus(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "_acme-challenge.node-a.example.com",
		Type:    "TXT",
		Value:   "token",
	})
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 without a MagicDNS domain", status)
	}
}

// TestSetDNSUnknownNodeIsRejected checks the identity binding: a record may only
// be published by a registered node in a live Noise session.
func TestSetDNSUnknownNodeIsRejected(t *testing.T) {
	s := newDNSAuthServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	machineKey := key.NewMachine()
	conn := dialNoise(t, hs, machineKey)
	defer conn.Close()

	client := h2Client(conn)
	_, status := postRawStatus(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Name:    "_acme-challenge.node-a.xunara.test",
		Type:    "TXT",
		Value:   "token",
	})
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unregistered node", status)
	}
	if got := len(s.Store().ListDNSRecords()); got != 0 {
		t.Errorf("stored records = %d, want 0", got)
	}
}
