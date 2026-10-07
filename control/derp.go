package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"tailscale.com/tailcfg"
)

// maxDERPAdmitRequestBytes bounds the admission request body. The body is a
// single node key plus an address; anything larger is abuse.
const maxDERPAdmitRequestBytes = 4 << 10

// handleDERPAdmit implements the DERP admission controller endpoint
// (POST /derp/admit) that Xunara Veil calls before admitting a DERP client,
// following the protocol of the upstream `derper --verify-client-url`.
//
// A client is admitted only when its node key belongs to a registered,
// unexpired node of this tailnet and the organization's DERP policy admits it
// (control/derp_policy.go). The endpoint deliberately fails closed:
// malformed requests and internal errors produce responses that
// [tailscale.com/derp/derpserver] treats as a rejection, never as an allow.
func (s *Server) handleDERPAdmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxDERPAdmitRequestBytes)

	var req tailcfg.DERPAdmitClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			http.Error(w, "empty admission request", http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid admission request", http.StatusBadRequest)
		return
	}

	allow := false
	if !req.NodePublic.IsZero() {
		if node, ok := s.store.GetNodeByNodeKey(req.NodePublic); ok && !node.Expired(time.Now()) {
			allow = s.derpPolicy.admits(node.HomeDERP, s.derpRegionKnown)
		}
	}

	// DERP handshakes are frequent enough that a rejected probe could be
	// noise; log at debug level with the short key form only.
	s.log.Debug("derp admission",
		"node", req.NodePublic.ShortString(),
		"source", req.Source.String(),
		"allow", allow,
	)

	writeJSON(w, http.StatusOK, tailcfg.DERPAdmitClientResponse{Allow: allow})
}
