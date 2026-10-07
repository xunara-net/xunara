// Package dnsprovider writes DNS records to external authoritative DNS
// servers on behalf of the control plane.
//
// The control plane itself is not an authoritative nameserver: it can answer
// MagicDNS queries inside the tailnet, but a public ACME certificate authority
// resolves the operator's zone on the public internet. These providers are how
// a "tailscale cert" DNS-01 challenge record reaches that zone.
package dnsprovider

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrMissingToken is returned when a provider needs an API token it does not
// have. Secrets are read from the environment by the caller, never from flags.
var ErrMissingToken = errors.New("dnsprovider: API token is required")

// ValidateHTTPURL checks that rawURL is an absolute http(s) URL and returns
// the parsed form. Plain http is only accepted for loopback addresses, so a
// misconfigured provider cannot leak its bearer token over the open network.
func ValidateHTTPURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("dnsprovider: invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("dnsprovider: URL scheme %q is not http(s)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("dnsprovider: URL has no host")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("dnsprovider: refusing to send credentials over plain http to %q", u.Hostname())
	}
	return u, nil
}

// validateRecordName checks a fully qualified record name.
func validateRecordName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("dnsprovider: empty record name")
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return errors.New("dnsprovider: record name must not start or end with a dot")
	}
	return nil
}

// isLoopbackHost reports whether host is a loopback name or address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
