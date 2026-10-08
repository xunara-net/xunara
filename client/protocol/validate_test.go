package protocol

import (
	"slices"
	"strings"
	"testing"
)

// TestValidateServicesCanonicalizes checks that a valid declaration comes back
// normalized: protocol case/whitespace folded, empty metadata nil.
func TestValidateServicesCanonicalizes(t *testing.T) {
	services, err := ValidateServices([]Service{
		{Name: "api", Protocol: " TCP ", Port: 8080, Metadata: map[string]string{"version": "1.2"},
			Visibility: []string{" tag:prod ", "group:eng", "tag:prod"}, Shared: true},
		{Name: "metrics", Protocol: "UDP", Port: 9090, VisibilityFromACL: true},
	})
	if err != nil {
		t.Fatalf("ValidateServices: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %+v", services)
	}
	if services[0].Protocol != "tcp" || services[1].Protocol != "udp" {
		t.Errorf("protocols = %q / %q, want lowercased", services[0].Protocol, services[1].Protocol)
	}
	if services[0].Metadata["version"] != "1.2" {
		t.Errorf("metadata = %+v", services[0].Metadata)
	}
	if services[1].Metadata != nil {
		t.Errorf("empty metadata = %+v, want nil", services[1].Metadata)
	}
	if !slices.Equal(services[0].Visibility, []string{"group:eng", "tag:prod"}) {
		t.Errorf("visibility = %v, want group:eng then tag:prod", services[0].Visibility)
	}
	if services[1].Visibility != nil {
		t.Errorf("default visibility = %v, want nil", services[1].Visibility)
	}
	if !services[0].Shared {
		t.Error("shared flag = false, want true")
	}
	if services[1].Shared {
		t.Error("default shared flag = true, want false")
	}
	if !services[1].VisibilityFromACL {
		t.Error("metrics visibilityFromACL = false, want true")
	}
	if services[0].VisibilityFromACL {
		t.Error("api visibilityFromACL = true, want false")
	}
}

// TestValidateServicesRejects declares the rules the client mirrors from the
// server: one bad entry fails the whole declaration.
func TestValidateServicesRejects(t *testing.T) {
	tooMany := make([]Service, MaxServicesPerNode+1)
	for i := range tooMany {
		tooMany[i] = Service{Name: "svc", Protocol: "tcp", Port: 1}
	}

	tooMuchMetadata := map[string]string{}
	for i := 0; i < MaxServiceMetadataEntries+1; i++ {
		tooMuchMetadata[string(rune('a'+i))] = "v"
	}

	cases := []struct {
		name     string
		services []Service
		want     string
	}{
		{"empty name", []Service{{Name: "", Protocol: "tcp", Port: 1}}, "empty"},
		{"uppercase name", []Service{{Name: "Api", Protocol: "tcp", Port: 1}}, "lowercase DNS label"},
		{"name too long", []Service{{Name: strings.Repeat("a", MaxServiceNameLen+1), Protocol: "tcp", Port: 1}}, "longer than"},
		{"leading hyphen", []Service{{Name: "-api", Protocol: "tcp", Port: 1}}, "hyphen"},
		{"bad protocol", []Service{{Name: "api", Protocol: "sctp", Port: 1}}, "unsupported protocol"},
		{"zero port", []Service{{Name: "api", Protocol: "tcp", Port: 0}}, "invalid port"},
		{"port out of range", []Service{{Name: "api", Protocol: "tcp", Port: 65536}}, "invalid port"},
		{"duplicate name", []Service{
			{Name: "api", Protocol: "tcp", Port: 1},
			{Name: "api", Protocol: "udp", Port: 2},
		}, "listed twice"},
		{"too many services", tooMany, "at most"},
		{"metadata key with space", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: map[string]string{"a b": "v"}},
		}, "metadata key"},
		{"metadata control character", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: map[string]string{"k": "a\x1bb"}},
		}, "metadata value"},
		{"metadata too many entries", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Metadata: tooMuchMetadata},
		}, "more than"},
		{"empty visibility selector", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{" "}},
		}, "empty"},
		{"visibility selector with control character", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"tag:a\x1b"}},
		}, "printable"},
		{"both visibility axes", []Service{
			{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"tag:a"}, VisibilityFromACL: true},
		}, "cannot be combined"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateServices(tc.services)
			if err == nil {
				t.Fatal("ValidateServices accepted an invalid declaration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}
