package state

import (
	"errors"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// storeFactory builds an empty store for conformance testing.
type storeFactory func(t *testing.T) Store

// runStoreConformance exercises the [Store] contract. Every implementation must
// pass it: the Compatibility Core only depends on the interface, so the
// implementations have to be interchangeable.
func runStoreConformance(t *testing.T, newStore storeFactory) {
	t.Run("create assigns identity", func(t *testing.T) {
		s := newStore(t)

		n := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "host1"}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}
		if n.ID == 0 {
			t.Error("expected an assigned ID")
		}
		if n.StableID == "" {
			t.Error("expected an assigned stable ID")
		}
		if !n.IPv4.IsValid() || !n.IPv6.IsValid() {
			t.Errorf("expected assigned addresses, got v4=%v v6=%v", n.IPv4, n.IPv6)
		}
		if n.Created.IsZero() {
			t.Error("expected a creation time")
		}

		byID, ok := s.GetNodeByID(n.ID)
		if !ok || byID.Hostname != "host1" {
			t.Errorf("GetNodeByID = %+v, %v", byID, ok)
		}
		byKey, ok := s.GetNodeByNodeKey(n.NodeKey)
		if !ok || byKey.ID != n.ID {
			t.Errorf("GetNodeByNodeKey = %+v, %v", byKey, ok)
		}
		byStable, ok := s.GetNodeByStableID(n.StableID)
		if !ok || byStable.ID != n.ID {
			t.Errorf("GetNodeByStableID = %+v, %v", byStable, ok)
		}
		if got := s.GetNodesByMachineKey(n.MachineKey); len(got) != 1 || got[0].ID != n.ID {
			t.Errorf("GetNodesByMachineKey = %+v", got)
		}
		if got := s.ListNodes(); len(got) != 1 {
			t.Errorf("ListNodes len = %d, want 1", len(got))
		}
		if got := n.FQDN(); got != "host1." {
			t.Errorf("FQDN = %q, want host1.", got)
		}
	})

	t.Run("create rejects duplicate node key", func(t *testing.T) {
		s := newStore(t)

		nk := key.NewNode().Public()
		if err := s.CreateNode(&Node{NodeKey: nk}); err != nil {
			t.Fatalf("first CreateNode: %v", err)
		}
		err := s.CreateNode(&Node{NodeKey: nk})
		if !errors.Is(err, ErrNodeKeyExists) {
			t.Fatalf("second CreateNode err = %v, want ErrNodeKeyExists", err)
		}
	})

	t.Run("create requires a node key", func(t *testing.T) {
		s := newStore(t)
		if err := s.CreateNode(&Node{}); err == nil {
			t.Fatal("expected an error for a node without a node key")
		}
	})

	t.Run("addresses are unique", func(t *testing.T) {
		s := newStore(t)

		seen := make(map[netip.Addr]bool)
		for i := range 16 {
			n := Node{NodeKey: key.NewNode().Public()}
			if err := s.CreateNode(&n); err != nil {
				t.Fatalf("CreateNode %d: %v", i, err)
			}
			if seen[n.IPv4] {
				t.Fatalf("duplicate IPv4 %v", n.IPv4)
			}
			seen[n.IPv4] = true
		}
	})

	t.Run("rich node round-trips", func(t *testing.T) {
		s := newStore(t)

		lastSeen := time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)
		expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
		n := Node{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			DiscoKey:   key.NewDisco().Public(),
			UserID:     DefaultUserID,
			Hostname:   "rich",
			Endpoints: []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.5:41641"),
				netip.MustParseAddrPort("[2001:db8::1]:41641"),
			},
			HomeDERP:  7,
			CapVer:    148,
			Hostinfo:  &tailcfg.Hostinfo{Hostname: "rich", OS: "linux", IPNVersion: "1.104.0"},
			LastSeen:  &lastSeen,
			Expiry:    expiry,
			Method:    RegisterMethodInteractive,
			Ephemeral: true,
		}

		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}

		got, ok := s.GetNodeByID(n.ID)
		if !ok {
			t.Fatal("node not found after create")
		}

		if !got.Created.Equal(n.Created) {
			t.Errorf("Created = %v, want %v", got.Created, n.Created)
		}
		if !got.Expiry.Equal(expiry) {
			t.Errorf("Expiry = %v, want %v", got.Expiry, expiry)
		}
		if got.LastSeen == nil || !got.LastSeen.Equal(lastSeen) {
			t.Errorf("LastSeen = %v, want %v", got.LastSeen, lastSeen)
		}
		if len(got.Endpoints) != 2 || got.Endpoints[0] != n.Endpoints[0] || got.Endpoints[1] != n.Endpoints[1] {
			t.Errorf("Endpoints = %v, want %v", got.Endpoints, n.Endpoints)
		}
		if got.HomeDERP != 7 || got.CapVer != 148 {
			t.Errorf("HomeDERP/CapVer = %d/%d, want 7/148", got.HomeDERP, got.CapVer)
		}
		if got.Hostinfo == nil || got.Hostinfo.OS != "linux" || got.Hostinfo.IPNVersion != "1.104.0" {
			t.Errorf("Hostinfo = %+v", got.Hostinfo)
		}
		if !got.Ephemeral {
			t.Error("Ephemeral = false, want true")
		}
		if got.Method != RegisterMethodInteractive {
			t.Errorf("Method = %q", got.Method)
		}
		if got.DiscoKey != n.DiscoKey {
			t.Error("DiscoKey did not round-trip")
		}
	})

	t.Run("plain node leaves optional fields empty", func(t *testing.T) {
		s := newStore(t)

		n := Node{NodeKey: key.NewNode().Public()}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}

		got, ok := s.GetNodeByID(n.ID)
		if !ok {
			t.Fatal("node not found")
		}
		if got.Hostinfo != nil {
			t.Errorf("Hostinfo = %+v, want nil", got.Hostinfo)
		}
		if got.LastSeen != nil {
			t.Errorf("LastSeen = %v, want nil", got.LastSeen)
		}
		if len(got.Endpoints) != 0 {
			t.Errorf("Endpoints = %v, want empty", got.Endpoints)
		}
		if !got.Expiry.IsZero() {
			t.Errorf("Expiry = %v, want zero", got.Expiry)
		}
	})

	t.Run("update replaces fields", func(t *testing.T) {
		s := newStore(t)

		n := Node{NodeKey: key.NewNode().Public(), Hostname: "before"}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}

		n.Hostname = "after"
		n.Ephemeral = true
		if err := s.UpdateNode(n); err != nil {
			t.Fatalf("UpdateNode: %v", err)
		}

		got, ok := s.GetNodeByID(n.ID)
		if !ok {
			t.Fatal("node not found")
		}
		if got.Hostname != "after" || !got.Ephemeral {
			t.Errorf("updated node = %+v", got)
		}
	})

	t.Run("update reindexes the node key", func(t *testing.T) {
		s := newStore(t)

		oldKey := key.NewNode().Public()
		n := Node{NodeKey: oldKey}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}

		n.NodeKey = key.NewNode().Public()
		if err := s.UpdateNode(n); err != nil {
			t.Fatalf("UpdateNode: %v", err)
		}

		if _, ok := s.GetNodeByNodeKey(oldKey); ok {
			t.Error("old node key still resolves")
		}
		if _, ok := s.GetNodeByNodeKey(n.NodeKey); !ok {
			t.Error("new node key does not resolve")
		}
	})

	t.Run("update rejects unknown node", func(t *testing.T) {
		s := newStore(t)
		err := s.UpdateNode(Node{ID: 9999, NodeKey: key.NewNode().Public()})
		if err == nil {
			t.Fatal("expected an error updating an unknown node")
		}
	})

	t.Run("delete removes from every index", func(t *testing.T) {
		s := newStore(t)

		n := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public()}
		if err := s.CreateNode(&n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}

		if err := s.DeleteNode(n.ID); err != nil {
			t.Fatalf("DeleteNode: %v", err)
		}

		if _, ok := s.GetNodeByID(n.ID); ok {
			t.Error("node still found by ID")
		}
		if _, ok := s.GetNodeByNodeKey(n.NodeKey); ok {
			t.Error("node still found by node key")
		}
		if _, ok := s.GetNodeByStableID(n.StableID); ok {
			t.Error("node still found by stable ID")
		}
		if got := s.GetNodesByMachineKey(n.MachineKey); len(got) != 0 {
			t.Errorf("GetNodesByMachineKey = %+v, want empty", got)
		}
		if got := s.ListNodes(); len(got) != 0 {
			t.Errorf("ListNodes = %+v, want empty", got)
		}

		// Deleting an unknown node is a no-op, matching the documented contract.
		if err := s.DeleteNode(n.ID); err != nil {
			t.Errorf("second DeleteNode: %v", err)
		}
	})

	t.Run("unknown lookups report absence", func(t *testing.T) {
		s := newStore(t)

		if _, ok := s.GetNodeByID(12345); ok {
			t.Error("GetNodeByID found a node that was never created")
		}
		if _, ok := s.GetNodeByNodeKey(key.NewNode().Public()); ok {
			t.Error("GetNodeByNodeKey found a node that was never created")
		}
		if _, ok := s.GetNodeByStableID("nope"); ok {
			t.Error("GetNodeByStableID found a node that was never created")
		}
		if got := s.GetNodesByMachineKey(key.NewMachine().Public()); len(got) != 0 {
			t.Errorf("GetNodesByMachineKey = %+v, want empty", got)
		}
	})

	t.Run("one machine key can back several nodes", func(t *testing.T) {
		s := newStore(t)

		mk := key.NewMachine().Public()
		first := Node{MachineKey: mk, NodeKey: key.NewNode().Public()}
		second := Node{MachineKey: mk, NodeKey: key.NewNode().Public()}
		if err := s.CreateNode(&first); err != nil {
			t.Fatalf("CreateNode first: %v", err)
		}
		if err := s.CreateNode(&second); err != nil {
			t.Fatalf("CreateNode second: %v", err)
		}

		got := s.GetNodesByMachineKey(mk)
		if len(got) != 2 {
			t.Fatalf("GetNodesByMachineKey len = %d, want 2", len(got))
		}

		if err := s.DeleteNode(first.ID); err != nil {
			t.Fatalf("DeleteNode: %v", err)
		}
		if got := s.GetNodesByMachineKey(mk); len(got) != 1 {
			t.Errorf("after delete len = %d, want 1", len(got))
		}
	})
}

// runPreAuthKeyConformance exercises the [PreAuthKeyStore] contract.
func runPreAuthKeyConformance(t *testing.T, newStore storeFactory) {
	t.Run("create assigns identity", func(t *testing.T) {
		s := newStore(t)

		k := PreAuthKey{Key: "tskey-auth-test", UserID: DefaultUserID, Reusable: true}
		if err := s.CreatePreAuthKey(&k); err != nil {
			t.Fatalf("CreatePreAuthKey: %v", err)
		}
		if k.ID == 0 {
			t.Error("expected an assigned ID")
		}
		if k.Created.IsZero() {
			t.Error("expected a creation time")
		}

		got, ok := s.GetPreAuthKey("tskey-auth-test")
		if !ok {
			t.Fatal("key not found after create")
		}
		if got.ID != k.ID || !got.Reusable || got.UserID != DefaultUserID {
			t.Errorf("round-trip = %+v, want %+v", got, k)
		}
	})

	t.Run("requires a secret", func(t *testing.T) {
		s := newStore(t)
		if err := s.CreatePreAuthKey(&PreAuthKey{}); err == nil {
			t.Fatal("expected an error for a key without a secret")
		}
	})

	t.Run("rejects duplicate secrets", func(t *testing.T) {
		s := newStore(t)

		if err := s.CreatePreAuthKey(&PreAuthKey{Key: "tskey-auth-dup"}); err != nil {
			t.Fatalf("first CreatePreAuthKey: %v", err)
		}
		err := s.CreatePreAuthKey(&PreAuthKey{Key: "tskey-auth-dup"})
		if !errors.Is(err, ErrPreAuthKeyExists) {
			t.Fatalf("second CreatePreAuthKey err = %v, want ErrPreAuthKeyExists", err)
		}
	})

	t.Run("mark used", func(t *testing.T) {
		s := newStore(t)

		k := PreAuthKey{Key: "tskey-auth-used"}
		if err := s.CreatePreAuthKey(&k); err != nil {
			t.Fatalf("CreatePreAuthKey: %v", err)
		}

		at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
		if err := s.MarkPreAuthKeyUsed(k.Key, at); err != nil {
			t.Fatalf("MarkPreAuthKeyUsed: %v", err)
		}

		got, ok := s.GetPreAuthKey(k.Key)
		if !ok {
			t.Fatal("key not found")
		}
		if !got.Used {
			t.Error("Used = false, want true")
		}
		if got.UsedAt == nil || !got.UsedAt.Equal(at) {
			t.Errorf("UsedAt = %v, want %v", got.UsedAt, at)
		}

		if err := s.MarkPreAuthKeyUsed("tskey-auth-missing", at); err == nil {
			t.Error("expected an error marking an unknown key used")
		}
	})

	t.Run("delete", func(t *testing.T) {
		s := newStore(t)

		k := PreAuthKey{Key: "tskey-auth-gone"}
		if err := s.CreatePreAuthKey(&k); err != nil {
			t.Fatalf("CreatePreAuthKey: %v", err)
		}

		if err := s.DeletePreAuthKey(k.Key); err != nil {
			t.Fatalf("DeletePreAuthKey: %v", err)
		}
		if _, ok := s.GetPreAuthKey(k.Key); ok {
			t.Error("key still found after delete")
		}
		if err := s.DeletePreAuthKey(k.Key); err != nil {
			t.Errorf("deleting an unknown key must be a no-op, got %v", err)
		}
	})

	t.Run("list is ordered by id", func(t *testing.T) {
		s := newStore(t)

		for _, secret := range []string{"tskey-auth-a", "tskey-auth-b", "tskey-auth-c"} {
			k := PreAuthKey{Key: secret}
			if err := s.CreatePreAuthKey(&k); err != nil {
				t.Fatalf("CreatePreAuthKey(%s): %v", secret, err)
			}
		}

		got := s.ListPreAuthKeys()
		if len(got) != 3 {
			t.Fatalf("ListPreAuthKeys len = %d, want 3", len(got))
		}
		for i := 1; i < len(got); i++ {
			if got[i-1].ID >= got[i].ID {
				t.Fatalf("keys are not ordered by ID: %+v", got)
			}
		}
	})

	t.Run("empty list", func(t *testing.T) {
		s := newStore(t)
		if got := s.ListPreAuthKeys(); len(got) != 0 {
			t.Errorf("ListPreAuthKeys = %+v, want empty", got)
		}
	})
}

func TestPreAuthKeyUsable(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		key  PreAuthKey
		want bool
	}{
		{"fresh", PreAuthKey{}, true},
		{"used single-use", PreAuthKey{Used: true}, false},
		{"used reusable", PreAuthKey{Used: true, Reusable: true}, true},
		{"expired", PreAuthKey{Expiry: now.Add(-time.Minute)}, false},
		{"expiry in future", PreAuthKey{Expiry: now.Add(time.Minute)}, true},
		{"expired and reusable", PreAuthKey{Reusable: true, Expiry: now.Add(-time.Minute)}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.key.Usable(now); got != tc.want {
				t.Errorf("Usable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewPreAuthKeySecretShape(t *testing.T) {
	seen := make(map[string]bool)

	for range 32 {
		secret, err := NewPreAuthKeySecret()
		if err != nil {
			t.Fatalf("NewPreAuthKeySecret: %v", err)
		}
		if !IsPreAuthKeySecret(secret) {
			t.Fatalf("secret %q does not look like a pre-auth key", secret)
		}
		if seen[secret] {
			t.Fatalf("duplicate secret generated: %q", secret)
		}
		seen[secret] = true

		// Official clients only redact secrets matching this pattern, so a
		// secret outside it would leak into logs.
		if !logRedactionPattern.MatchString(secret) {
			t.Errorf("secret %q is not redacted by official clients", secret)
		}
	}
}

// logRedactionPattern is the pattern official Tailscale clients use to redact
// secrets from their output (cmd/tailscale/cli/cli.go).
var logRedactionPattern = regexp.MustCompile(`tskey-[A-Za-z0-9-]+`)
