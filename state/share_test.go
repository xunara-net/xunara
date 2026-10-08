package state

import (
	"net/netip"
	"path/filepath"
	"testing"

	"tailscale.com/types/key"
)

// TestShareAddressAtOffset checks the masquerade allocator stays inside its
// reserved ranges, is deterministic, and reports exhaustion at the edge.
func TestShareAddressAtOffset(t *testing.T) {
	v4, v6, err := shareAddressAtOffset(0)
	if err != nil {
		t.Fatalf("shareAddressAtOffset(0): %v", err)
	}
	if !ShareMasqIPv4Prefix.Contains(v4) || !ShareMasqIPv6Prefix.Contains(v6) {
		t.Fatalf("first pair %v/%v is outside the share ranges", v4, v6)
	}
	if v4 == ShareMasqIPv4Prefix.Addr() || v6 == ShareMasqIPv6Prefix.Addr() {
		t.Errorf("first pair reuses the network address: %v/%v", v4, v6)
	}

	again, _, err := shareAddressAtOffset(0)
	if err != nil || again != v4 {
		t.Errorf("shareAddressAtOffset(0) = %v (%v), want the same %v", again, err, v4)
	}
	other, _, err := shareAddressAtOffset(1)
	if err != nil || other == v4 {
		t.Errorf("shareAddressAtOffset(1) = %v (%v), want a fresh address", other, err)
	}
	if !isShareMasqAddr(v4) || !isShareMasqAddr(v6) {
		t.Errorf("isShareMasqAddr rejected an allocated pair %v/%v", v4, v6)
	}
	if isShareMasqAddr(netip.MustParseAddr("100.64.0.1")) || isShareMasqAddr(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Error("isShareMasqAddr matched an ordinary tailnet address")
	}

	// The last index fills the last host address of the range; the next one
	// must fail rather than wrap into an address outside it.
	last, _, err := shareAddressAtOffset(1<<16 - 2)
	if err != nil {
		t.Fatalf("last shareAddressAtOffset: %v", err)
	}
	if last != netip.MustParseAddr("100.127.255.255") {
		t.Errorf("last share IPv4 = %v, want 100.127.255.255", last)
	}
	if _, _, err := shareAddressAtOffset(1<<16 - 1); err == nil {
		t.Error("shareAddressAtOffset accepted an out-of-range index")
	}
}

// TestIPAllocatorSkipsShareRange checks the node allocator never hands out a
// masquerade address, even when the local prefix is exactly the share range.
func TestIPAllocatorSkipsShareRange(t *testing.T) {
	a := &ipAllocator{prefix: ShareMasqIPv4Prefix, last: ShareMasqIPv4Prefix.Masked().Addr()}
	if addr, ok := a.next(); ok {
		t.Fatalf("allocator returned a reserved address: %v", addr)
	}
}

// TestCreateNodeSkipsShareRange walks a memory store's IPv4 allocator up to
// the reserved range and checks it fails closed instead of handing out a
// masquerade address. (The reserved /16 is the last one of the default
// 100.64.0.0/10 pool, so exhaustion is the honest outcome at the edge.)
func TestCreateNodeSkipsShareRange(t *testing.T) {
	s := NewMemoryStore()
	s.ip4.last = netip.MustParseAddr("100.126.255.254")

	last := Node{NodeKey: key.NewNode().Public(), UserID: DefaultUserID}
	if err := s.CreateNode(&last); err != nil {
		t.Fatalf("CreateNode(last free address): %v", err)
	}
	if last.IPv4 != netip.MustParseAddr("100.126.255.255") {
		t.Fatalf("last free address = %v, want 100.126.255.255", last.IPv4)
	}
	if isShareMasqAddr(last.IPv4) || isShareMasqAddr(last.IPv6) {
		t.Errorf("node got a reserved address: %v/%v", last.IPv4, last.IPv6)
	}

	overflow := Node{NodeKey: key.NewNode().Public(), UserID: DefaultUserID}
	if err := s.CreateNode(&overflow); err == nil {
		t.Fatalf("CreateNode inside the reserved range = %v/%v, want exhaustion", overflow.IPv4, overflow.IPv6)
	}
}

// TestMemoryShareStore checks the in-memory share namespace: stable per key,
// unique across keys and organizations, with synthetic IDs above the base.
func TestMemoryShareStore(t *testing.T) {
	s := NewMemoryStore()

	id, err := s.EnsureShareNode("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareNode: %v", err)
	}
	if id < ShareNodeIDBase {
		t.Errorf("synthetic node ID = %d, want >= %d", id, ShareNodeIDBase)
	}
	again, err := s.EnsureShareNode("acme", "node-a")
	if err != nil || again != id {
		t.Errorf("EnsureShareNode repeat = %d (%v), want %d", again, err, id)
	}
	other, err := s.EnsureShareNode("acme", "node-b")
	if err != nil || other == id {
		t.Errorf("EnsureShareNode(other key) = %d (%v), want a fresh ID", other, err)
	}
	foreign, err := s.EnsureShareNode("globex", "node-a")
	if err != nil || foreign == id {
		t.Errorf("EnsureShareNode(other org) = %d (%v), want a fresh ID", foreign, err)
	}
	if got, ok := s.ShareNode("acme", "node-a"); !ok || got != id {
		t.Errorf("ShareNode = %d, %v, want %d, true", got, ok, id)
	}
	if _, ok := s.ShareNode("acme", "missing"); ok {
		t.Error("ShareNode returned an unknown key")
	}

	v4, v6, err := s.EnsureShareAddress("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareAddress: %v", err)
	}
	againV4, againV6, err := s.EnsureShareAddress("acme", "node-a")
	if err != nil || againV4 != v4 || againV6 != v6 {
		t.Errorf("EnsureShareAddress repeat = %v/%v (%v), want %v/%v", againV4, againV6, err, v4, v6)
	}
	if got4, got6, ok := s.ShareAddress("acme", "node-a"); !ok || got4 != v4 || got6 != v6 {
		t.Errorf("ShareAddress = %v/%v, %v, want %v/%v, true", got4, got6, ok, v4, v6)
	}
	if _, _, ok := s.ShareAddress("acme", "missing"); ok {
		t.Error("ShareAddress returned an unknown key")
	}
}

// TestSQLiteShareStorePersists checks the durable share namespace survives a
// restart with the same identifiers and addresses.
func TestSQLiteShareStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first := openTestSQLite(t, path)

	wantNode, err := first.EnsureShareNode("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareNode: %v", err)
	}
	wantV4, wantV6, err := first.EnsureShareAddress("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareAddress: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	gotNode, err := second.EnsureShareNode("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareNode after reopen: %v", err)
	}
	if gotNode != wantNode {
		t.Errorf("synthetic node ID after reopen = %d, want %d", gotNode, wantNode)
	}
	gotV4, gotV6, err := second.EnsureShareAddress("acme", "node-a")
	if err != nil {
		t.Fatalf("EnsureShareAddress after reopen: %v", err)
	}
	if gotV4 != wantV4 || gotV6 != wantV6 {
		t.Errorf("masquerade after reopen = %v/%v, want %v/%v", gotV4, gotV6, wantV4, wantV6)
	}
	// A fresh key gets a fresh allocation, not the reopened one.
	fresh, err := second.EnsureShareNode("acme", "node-b")
	if err != nil || fresh == wantNode {
		t.Errorf("fresh allocation = %d (%v), want a new ID", fresh, err)
	}
}
