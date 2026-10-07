package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara/xunara/state"
)

// tkaRPC performs a tailnet-lock RPC (GET with a JSON body, over the Noise
// session) and returns the raw response, failing the test on an unexpected
// status.
func tkaRPC(t *testing.T, client *http.Client, path string, req any, wantStatus int) []byte {
	t.Helper()

	out, code := doRaw(t, client, http.MethodGet, path, req)
	if code != wantStatus {
		t.Fatalf("GET %s = %d (%s), want %d", path, code, out, wantStatus)
	}
	return out
}

// tkaJSON performs a TKA RPC and decodes its JSON response into T.
func tkaJSON[T any](t *testing.T, client *http.Client, path string, req any, wantStatus int) T {
	t.Helper()

	var out T
	if err := json.Unmarshal(tkaRPC(t, client, path, req, wantStatus), &out); err != nil {
		t.Fatalf("decoding %s response: %v", path, err)
	}
	return out
}

// nodeIDOf returns the stored node ID for a node key.
func nodeIDOf(t *testing.T, s *Server, nodeKey key.NodePublic) tailcfg.NodeID {
	t.Helper()

	node, ok := s.store.GetNodeByNodeKey(nodeKey)
	if !ok {
		t.Fatalf("node %v is not registered", nodeKey.ShortString())
	}
	return tailcfg.NodeID(node.ID)
}

// fullMapFor fetches a node's full netmap.
func fullMapFor(t *testing.T, client *http.Client, nodeKey key.NodePublic) *tailcfg.MapResponse {
	t.Helper()

	return decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
	}), "")
}

// peerByKey finds a peer in a netmap by node key.
func peerByKey(resp *tailcfg.MapResponse, nodeKey key.NodePublic) *tailcfg.Node {
	for _, p := range resp.Peers {
		if p.Key == nodeKey {
			return p
		}
	}
	return nil
}

// TestTailnetLockEndToEnd drives the full tailnet-lock lifecycle through the
// inner machine API: enablement, netmap advertisement, synchronization,
// signing, and disablement.
func TestTailnetLockEndToEnd(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "lock-admin")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "lock-peer")
	defer connB.Close()

	adminKey, genesis := newTestTKAKey(t)
	genesisHead := genesis.Hash().String()

	// Enablement, phase 1: submit the genesis AUM. Control must collect
	// signatures for the nodes that already exist before enforcing.
	begin := tkaJSON[tailcfg.TKAInitBeginResponse](t, clientA, "/machine/tka/init/begin", tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKeyA.Public(),
		GenesisAUM: genesis.Serialize(),
	}, http.StatusOK)
	if len(begin.NeedSignatures) != 2 {
		t.Fatalf("NeedSignatures = %+v, want both existing nodes", begin.NeedSignatures)
	}

	// Until init/finish the chain exists but is not advertised: the tailnet
	// keeps working while the administrator signs everyone.
	if got := fullMapFor(t, clientA, nodeKeyA.Public()); got.TKAInfo != nil {
		t.Errorf("TKAInfo before init/finish = %+v, want none", got.TKAInfo)
	}
	if _, ok := fullMapFor(t, clientA, nodeKeyA.Public()).Node.CapMap[tailcfg.CapabilityTailnetLock]; ok {
		t.Error("tailnet lock capability advertised before init/finish")
	}

	// Phase 2: sign every existing node and turn enforcement on.
	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{
		nodeIDOf(t, s, nodeKeyA.Public()): signTestNodeKey(t, adminKey, nodeKeyA.Public()),
		nodeIDOf(t, s, nodeKeyB.Public()): signTestNodeKey(t, adminKey, nodeKeyB.Public()),
	}
	tkaRPC(t, clientA, "/machine/tka/init/finish", tailcfg.TKAInitFinishRequest{
		Version:            tailcfg.CurrentCapabilityVersion,
		NodeKey:            nodeKeyA.Public(),
		Signatures:         sigs,
		SupportDisablement: testDisablementSecret,
	}, http.StatusOK)

	mapA := fullMapFor(t, clientA, nodeKeyA.Public())
	if mapA.TKAInfo == nil || mapA.TKAInfo.Head != genesisHead || mapA.TKAInfo.Disabled {
		t.Fatalf("TKAInfo = %+v, want the current head %q", mapA.TKAInfo, genesisHead)
	}
	if _, ok := mapA.Node.CapMap[tailcfg.CapabilityTailnetLock]; !ok {
		t.Errorf("self CapMap = %v, want %s", mapA.Node.CapMap, tailcfg.CapabilityTailnetLock)
	}
	if !bytes.Equal(mapA.Node.KeySignature, sigs[nodeIDOf(t, s, nodeKeyA.Public())]) {
		t.Error("self node does not carry the signature submitted at init/finish")
	}
	peerB := peerByKey(mapA, nodeKeyB.Public())
	if peerB == nil {
		t.Fatal("peer B is missing from the netmap")
	}
	if !bytes.Equal(peerB.KeySignature, sigs[nodeIDOf(t, s, nodeKeyB.Public())]) {
		t.Error("peer B does not carry its signature")
	}
	if peerB.UnsignedPeerAPIOnly {
		t.Error("signed peer B is marked UnsignedPeerAPIOnly")
	}

	// A node bootstraps the genesis AUM to enable tailnet lock locally.
	bs := tkaJSON[tailcfg.TKABootstrapResponse](t, clientB, "/machine/tka/bootstrap", tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyB.Public(),
	}, http.StatusOK)
	if !bytes.Equal(bs.GenesisAUM, genesis.Serialize()) {
		t.Error("bootstrap returned a different genesis AUM")
	}
	if len(bs.DisablementSecret) != 0 {
		t.Error("bootstrap handed out a disablement secret before any disablement")
	}

	// A device that joins without a signature is confined to the peer API:
	// peers must not be able to route to it, or their clients would reject
	// the whole packet filter.
	connC, clientC, nodeKeyC := registerNode(t, s, hs, "lock-unsigned")
	defer connC.Close()

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	peerC := peerByKey(mapA, nodeKeyC.Public())
	if peerC == nil {
		t.Fatal("unsigned node C is missing from the netmap")
	}
	if !peerC.UnsignedPeerAPIOnly {
		t.Error("unsigned node C is not marked UnsignedPeerAPIOnly")
	}
	// The signed nodes must stay reachable: the wildcard sources expand to
	// exactly their addresses.
	for _, want := range []string{mapA.Node.Addresses[0].String(), peerB.Addresses[0].String()} {
		if !slices.Contains(mapA.PacketFilters["base"][0].SrcIPs, want) {
			t.Errorf("packet filter sources %v do not include the signed node %s",
				mapA.PacketFilters["base"][0].SrcIPs, want)
		}
	}

	cAddr := netip.PrefixFrom(peerC.Addresses[0].Addr(), peerC.Addresses[0].Addr().BitLen())
	for _, rule := range mapA.PacketFilters["base"] {
		for _, src := range rule.SrcIPs {
			if src == "*" {
				t.Errorf("packet filter still permits a wildcard source: %+v", rule)
				continue
			}
			p, err := netip.ParsePrefix(src)
			if err != nil {
				t.Errorf("packet filter source %q is not a prefix", src)
				continue
			}
			if p.Overlaps(cAddr) {
				t.Errorf("packet filter permits unsigned peer %v: %+v", cAddr, rule)
			}
		}
	}

	// Synchronization: C offers the genesis head, then pulls the update.
	offer := tkaJSON[tailcfg.TKASyncOfferResponse](t, clientC, "/machine/tka/sync/offer", tailcfg.TKASyncOfferRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyC.Public(),
		Head:    genesisHead,
	}, http.StatusOK)
	if offer.Head != genesisHead || len(offer.MissingAUMs) != 0 {
		t.Fatalf("sync offer = %+v, want an up-to-date node", offer)
	}

	// Announce a new chain update (as `tailscale lock revoke-keys` would) and
	// check the node pulls it, then reports it back.
	commitTestAUM(t, s, adminKey)
	newHead := s.tka.view().Head
	offer = tkaJSON[tailcfg.TKASyncOfferResponse](t, clientC, "/machine/tka/sync/offer", tailcfg.TKASyncOfferRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyC.Public(),
		Head:    genesisHead,
	}, http.StatusOK)
	if len(offer.MissingAUMs) != 1 || offer.Head != newHead {
		t.Fatalf("sync offer after an update = %+v, want one missing AUM at %q", offer, newHead)
	}
	send := tkaJSON[tailcfg.TKASyncSendResponse](t, clientC, "/machine/tka/sync/send", tailcfg.TKASyncSendRequest{
		Version:     tailcfg.CurrentCapabilityVersion,
		NodeKey:     nodeKeyC.Public(),
		Head:        newHead,
		MissingAUMs: offer.MissingAUMs,
	}, http.StatusOK)
	if send.Head != newHead {
		t.Errorf("sync send head = %q, want %q", send.Head, newHead)
	}

	// An administrator signs C, which un-confines it.
	tkaRPC(t, clientA, "/machine/tka/sign", tailcfg.TKASubmitSignatureRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   nodeKeyA.Public(),
		Signature: signTestNodeKey(t, adminKey, nodeKeyC.Public()),
	}, http.StatusOK)

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	if peerC = peerByKey(mapA, nodeKeyC.Public()); peerC == nil || peerC.UnsignedPeerAPIOnly {
		t.Fatalf("node C after signing = %+v, want a signed peer", peerC)
	}
	// C now sees its own signature too, which clients need to verify
	// themselves against the chain.
	mapC := fullMapFor(t, clientC, nodeKeyC.Public())
	if len(mapC.Node.KeySignature) == 0 {
		t.Error("signed node C has no self node-key signature")
	}

	// affected-sigs lists every signature the key made.
	affected := tkaJSON[tailcfg.TKASignaturesUsingKeyResponse](t, clientA, "/machine/tka/affected-sigs", tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
		KeyID:   adminKey.KeyID(),
	}, http.StatusOK)
	if len(affected.Signatures) != 3 {
		t.Errorf("affected signatures = %d, want 3", len(affected.Signatures))
	}
	other := tkaJSON[tailcfg.TKASignaturesUsingKeyResponse](t, clientA, "/machine/tka/affected-sigs", tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
		KeyID:   key.NewNLPrivate().KeyID(),
	}, http.StatusOK)
	if len(other.Signatures) != 0 {
		t.Errorf("signatures for an untrusted key = %d, want 0", len(other.Signatures))
	}

	// Disablement: a wrong secret is refused, the generated one works, and
	// clients are told to clear their local state.
	tkaRPC(t, clientA, "/machine/tka/disable", tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nodeKeyA.Public(),
		Head:              newHead,
		DisablementSecret: []byte("not-the-secret"),
	}, http.StatusForbidden)
	tkaRPC(t, clientA, "/machine/tka/disable", tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nodeKeyA.Public(),
		Head:              newHead,
		DisablementSecret: testDisablementSecret,
	}, http.StatusOK)

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	if mapA.TKAInfo == nil || !mapA.TKAInfo.Disabled {
		t.Fatalf("TKAInfo after disablement = %+v, want Disabled", mapA.TKAInfo)
	}
	if peerC = peerByKey(mapA, nodeKeyC.Public()); peerC == nil || peerC.UnsignedPeerAPIOnly {
		t.Errorf("peer after disablement = %+v, want no unsigned confinement", peerC)
	}
	// The chain is kept, so a node that is still enabled locally can fetch
	// the secret and clear its state.
	bs = tkaJSON[tailcfg.TKABootstrapResponse](t, clientA, "/machine/tka/bootstrap", tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
	}, http.StatusOK)
	if !bytes.Equal(bs.GenesisAUM, genesis.Serialize()) {
		t.Error("bootstrap lost the genesis AUM after disablement")
	}
	if !bytes.Equal(bs.DisablementSecret, testDisablementSecret) {
		t.Error("bootstrap did not hand out the disablement secret")
	}
}

// commitTestAUM appends a new key to the tailnet's authority, as an
// interactive `tailscale lock revoke-keys` would through sync/send.
func commitTestAUM(t *testing.T, s *Server, signer key.NLPrivate) {
	t.Helper()

	updater := s.tka.authority.NewUpdater(signer)
	newKey := key.NewNLPrivate()
	if err := updater.AddKey(tka.Key{Kind: tka.Key25519, Public: newKey.Public().Verifier(), Votes: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	updates, err := updater.Finalize(s.tka.chonk)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := s.tka.authority.Inform(s.tka.chonk, updates); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	s.notifyWatchers()
}

// TestTailnetLockStreamsTransitions checks that a client with a live netmap
// stream is told about tailnet-lock transitions: nil means "unchanged" in a
// delta response, so an enablement and a disablement must both arrive as
// explicit non-nil frames.
func TestTailnetLockStreamsTransitions(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "lock-stream")
	defer conn.Close()

	sess := openMapSession(t, client, nodeKey.Public())
	defer sess.Body.Close()
	frames := mapFrames(sess.Body)

	first := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool { return m.Node != nil })
	if first.TKAInfo != nil {
		t.Errorf("TKAInfo before enablement = %+v, want none", first.TKAInfo)
	}
	if _, ok := first.Node.CapMap[tailcfg.CapabilityTailnetLock]; ok {
		t.Error("tailnet lock capability advertised before enablement")
	}

	// Enabling tailnet lock out-of-band must reach the running session.
	_, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	s.notifyWatchers()

	on := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool {
		return m.TKAInfo != nil && !m.TKAInfo.Disabled
	})
	if on.TKAInfo.Head != genesis.Hash().String() {
		t.Errorf("TKAInfo.Head = %q, want %q", on.TKAInfo.Head, genesis.Hash().String())
	}
	if on.Node == nil {
		t.Fatal("the enablement frame must carry the self node with the new capability")
	}
	if _, ok := on.Node.CapMap[tailcfg.CapabilityTailnetLock]; !ok {
		t.Errorf("self CapMap = %v, want %s", on.Node.CapMap, tailcfg.CapabilityTailnetLock)
	}

	// Disablement must be explicit too.
	if err := s.tka.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}
	s.notifyWatchers()

	off := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool {
		return m.TKAInfo != nil && m.TKAInfo.Disabled
	})
	if off.TKAInfo.Head != "" {
		t.Errorf("disabled TKAInfo still carries head %q", off.TKAInfo.Head)
	}
}

// TestTailnetLockRegistrationSignatures checks the registration half of the
// protocol: a verifying node-key signature is stored and published, and an
// unverifiable one is refused instead of silently downgrading the node to
// unsigned.
func TestTailnetLockRegistrationSignatures(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "lock-admin")
	defer connA.Close()

	adminKey, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{
		nodeIDOf(t, s, nodeKeyA.Public()): signTestNodeKey(t, adminKey, nodeKeyA.Public()),
	}
	tkaRPC(t, clientA, "/machine/tka/init/finish", tailcfg.TKAInitFinishRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKeyA.Public(),
		Signatures: sigs,
	}, http.StatusOK)

	// A node joining with a pre-auth key and a valid tailnet-lock credential
	// is signed from the start.
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKeyD := key.NewMachine()
	nodeKeyD := key.NewNode()
	connD := dialNoise(t, hs, machineKeyD)
	defer connD.Close()
	clientD := h2Client(connD)

	sigD := signTestNodeKey(t, adminKey, nodeKeyD.Public())
	regD := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, clientD, "/machine/register", tailcfg.RegisterRequest{
		Version:          tailcfg.CurrentCapabilityVersion,
		NodeKey:          nodeKeyD.Public(),
		NodeKeySignature: sigD,
		Auth:             &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}))
	if !regD.MachineAuthorized {
		t.Fatalf("registration with a valid signature failed: %+v", regD)
	}
	if got := fullMapFor(t, clientD, nodeKeyD.Public()).Node.KeySignature; !bytes.Equal(got, sigD) {
		t.Error("the signature presented at registration did not reach the netmap")
	}

	// A signature made by a key the tailnet does not trust is refused, and no
	// node is created.
	secretE := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKeyE := key.NewMachine()
	nodeKeyE := key.NewNode()
	connE := dialNoise(t, hs, machineKeyE)
	defer connE.Close()
	clientE := h2Client(connE)

	regE := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, clientE, "/machine/register", tailcfg.RegisterRequest{
		Version:          tailcfg.CurrentCapabilityVersion,
		NodeKey:          nodeKeyE.Public(),
		NodeKeySignature: signTestNodeKey(t, key.NewNLPrivate(), nodeKeyE.Public()),
		Auth:             &tailcfg.RegisterResponseAuth{AuthKey: secretE},
	}))
	if regE.Error == "" {
		t.Fatalf("registration with an untrusted signature was accepted: %+v", regE)
	}
	if _, ok := s.store.GetNodeByNodeKey(nodeKeyE.Public()); ok {
		t.Error("a rejected registration still created a node")
	}
}
