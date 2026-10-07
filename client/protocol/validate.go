package protocol

// This file holds the client-side view of the declaration rules the control
// plane enforces (control/services.go). They exist so a client can reject an
// obviously wrong declaration before a network round trip; the server remains
// the authority and validates every publish again.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	// MaxServicesPerNode bounds how many services one node may advertise.
	MaxServicesPerNode = 32
	// MaxServiceNameLen bounds a service name: it becomes a DNS label.
	MaxServiceNameLen = 63
	// MaxServiceMetadataEntries bounds one service's metadata map.
	MaxServiceMetadataEntries = 16
	// MaxServiceMetadataKeyLen bounds a metadata key (printable ASCII
	// without spaces).
	MaxServiceMetadataKeyLen = 64
	// MaxServiceMetadataValueLen bounds a metadata value.
	MaxServiceMetadataValueLen = 256
	// MaxServiceMetadataBytes bounds the encoded metadata of one service.
	MaxServiceMetadataBytes = 2 << 10
)

// ValidateServices validates a declaration and returns its canonical form:
// protocols are lowercased and trimmed, empty metadata becomes nil. Every rule
// is fail-closed, matching the control plane: one bad entry fails the whole
// declaration.
func ValidateServices(services []Service) ([]Service, error) {
	if len(services) > MaxServicesPerNode {
		return nil, fmt.Errorf("at most %d services may be advertised per node", MaxServicesPerNode)
	}

	out := make([]Service, 0, len(services))
	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if err := validateServiceName(svc.Name); err != nil {
			return nil, err
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("service name %q is listed twice", svc.Name)
		}
		seen[svc.Name] = true

		proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("service %q has an unsupported protocol %q", svc.Name, svc.Protocol)
		}
		if svc.Port == 0 || svc.Port > 65535 {
			return nil, fmt.Errorf("service %q has an invalid port", svc.Name)
		}
		metadata, err := validateServiceMetadata(svc.Metadata)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}

		out = append(out, Service{Name: svc.Name, Protocol: proto, Port: svc.Port, Metadata: metadata})
	}
	return out, nil
}

// validateServiceName enforces the DNS label shape a service name must have.
func validateServiceName(name string) error {
	if name == "" {
		return errors.New("service name is empty")
	}
	if len(name) > MaxServiceNameLen {
		return fmt.Errorf("service name is longer than %d bytes", MaxServiceNameLen)
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

// validateServiceMetadata bounds and cleans one service's metadata: printable
// ASCII only, so terminal surfaces cannot be made to render escape sequences.
func validateServiceMetadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	if len(metadata) > MaxServiceMetadataEntries {
		return nil, fmt.Errorf("metadata has more than %d entries", MaxServiceMetadataEntries)
	}

	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if key == "" || len(key) > MaxServiceMetadataKeyLen || !printableASCII(key, false) {
			return nil, fmt.Errorf("metadata key %q is invalid", sanitizeServiceName(key))
		}
		if len(value) > MaxServiceMetadataValueLen || !printableASCII(value, true) {
			return nil, fmt.Errorf("metadata value of %q is invalid", sanitizeServiceName(key))
		}
		out[key] = value
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, errors.New("metadata cannot be encoded")
	}
	if len(encoded) > MaxServiceMetadataBytes {
		return nil, fmt.Errorf("metadata is larger than %d bytes", MaxServiceMetadataBytes)
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
