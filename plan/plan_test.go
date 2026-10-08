package plan

import (
	"strings"
	"testing"
)

func TestValidateRejectsBrokenPlans(t *testing.T) {
	for _, tt := range []struct {
		name string
		plan Plan
		want string
	}{
		{"missing id", Plan{Name: "Free"}, "id is required"},
		{"missing name", Plan{ID: "free"}, "name is required"},
		{"negative price", Plan{ID: "p", Name: "P", PriceCents: -1}, "price"},
		{"bad cycle", Plan{ID: "p", Name: "P", BillingCycle: "week"}, "billing cycle"},
		{"quota below unlimited", Plan{ID: "p", Name: "P", MaxDevices: -5}, "max_devices"},
		{"unlimited is fine", Plan{ID: "p", Name: "P", MaxDevices: Unlimited, MaxUsers: Unlimited, MaxRoutes: Unlimited, MaxAuthKeys: Unlimited}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plan.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate = %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}

func TestDeviceQuota(t *testing.T) {
	free := Plan{ID: "free", Name: "Free", MaxDevices: 10}
	if !free.AllowsDevices(9) {
		t.Error("the 10th device was refused on a 10-device plan")
	}
	if free.AllowsDevices(10) {
		t.Error("the 11th device was allowed on a 10-device plan")
	}
	if got := free.DeviceAllowance(); got != "10" {
		t.Errorf("DeviceAllowance = %q, want 10", got)
	}

	none := Plan{ID: "none", Name: "None", MaxDevices: 0}
	if none.AllowsDevices(0) {
		t.Error("a zero-device plan allowed a device")
	}

	unlimited := Plan{ID: "u", Name: "U", MaxDevices: Unlimited}
	if !unlimited.AllowsDevices(1 << 20) {
		t.Error("an unlimited plan refused a device")
	}
	if got := unlimited.DeviceAllowance(); got != "unlimited" {
		t.Errorf("DeviceAllowance = %q, want unlimited", got)
	}
}

func TestParseCatalogRefusesUnknownFields(t *testing.T) {
	raw := []byte(`{"plans":[{"id":"free","name":"Free","max_devices":10,"max_deivces":5}]}`)
	if _, err := ParseCatalog(raw); err == nil {
		t.Fatal("ParseCatalog accepted an unknown field (a typo would silently drop a limit)")
	}
}

func TestParseCatalogAndDefaults(t *testing.T) {
	raw := []byte(`{"plans":[
		{"id":"small","name":"Small","max_devices":2,"max_users":1},
		{"id":"big","name":"Big","price_cents":9900,"currency":"CNY","billing_cycle":"month",
		 "max_devices":50,"allow_exit_node":true}
	]}`)
	c, err := ParseCatalog(raw)
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	if got := c.Default().ID; got != "small" {
		t.Errorf("Default = %q, want the first plan (small)", got)
	}
	if big, ok := c.Get("big"); !ok || !big.AllowExitNode || big.MaxDevices != 50 {
		t.Errorf("Get(big) = %+v, %v", big, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("Get returned an unknown plan")
	}
	if got := len(c.List()); got != 2 {
		t.Errorf("List returned %d plans, want 2", got)
	}

	if _, err := ParseCatalog([]byte(`{"plans":[
		{"id":"dup","name":"A"},{"id":"dup","name":"B"}]}`)); err == nil {
		t.Error("ParseCatalog accepted duplicate plan IDs")
	}
	if _, err := ParseCatalog([]byte(`{"plans":[]}`)); err == nil {
		t.Error("ParseCatalog accepted an empty catalog")
	}
}

func TestDefaultCatalogMatchesTheProductModel(t *testing.T) {
	c := DefaultCatalog()
	free, ok := c.Get(FreeID)
	if !ok {
		t.Fatal("the built-in catalog has no free plan")
	}
	if free.MaxDevices != 10 {
		t.Errorf("free plan devices = %d, want 10", free.MaxDevices)
	}
	if free.AllowCustomCIDR || free.AllowExitNode || free.AllowMultiMember {
		t.Errorf("free plan allows paid features: %+v", free)
	}
	if free.AllowsDevices(10) {
		t.Error("the free plan allows 11 devices")
	}
	pro, _ := c.Get(ProID)
	if !pro.AllowCustomCIDR || !pro.AllowExitNode || !pro.AllowMultiMember {
		t.Errorf("pro plan is missing paid features: %+v", pro)
	}
	business, _ := c.Get(BusinessID)
	if business.MaxDevices <= pro.MaxDevices || business.MaxUsers <= pro.MaxUsers {
		t.Errorf("business plan is not larger than pro: %+v vs %+v", business, pro)
	}
}

func TestNilCatalogIsSafe(t *testing.T) {
	var c *Catalog
	if _, ok := c.Get(FreeID); ok {
		t.Error("a nil catalog returned a plan")
	}
	if got := c.Default(); got.MaxDevices != Unlimited {
		t.Errorf("a nil catalog default = %+v, want unlimited", got)
	}
	if c.List() != nil {
		t.Error("a nil catalog listed plans")
	}
}
