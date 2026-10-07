package control

import (
	"fmt"
	"net/http"
	"strconv"

	"tailscale.com/tailcfg"
)

// MinSupportedCapabilityVersion is the oldest client capability version Xunara
// completes a TS2021 handshake with.
//
// This mirrors headscale's floor (reference/headscale/hscontrol/capver) and the
// upstream full-netmap semantics from tailscale/tailscale#15660. Clients below
// the floor are rejected at /key and at the Noise handshake rather than being
// handed a key that only acts as a version-boundary oracle.
const MinSupportedCapabilityVersion tailcfg.CapabilityVersion = 115

// isSupportedVersion reports whether Xunara will serve a client advertising v.
func isSupportedVersion(v tailcfg.CapabilityVersion) bool {
	return v >= MinSupportedCapabilityVersion
}

// parseCapabilityVersion reads the client capability version from the "v" query
// parameter, as sent by official clients when fetching /key.
func parseCapabilityVersion(req *http.Request) (tailcfg.CapabilityVersion, error) {
	raw := req.URL.Query().Get("v")
	if raw == "" {
		return 0, NewHTTPError(http.StatusBadRequest, "capability version must be set", nil)
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, NewHTTPError(
			http.StatusBadRequest,
			"invalid capability version",
			fmt.Errorf("parsing capability version: %w", err),
		)
	}

	return tailcfg.CapabilityVersion(n), nil
}
