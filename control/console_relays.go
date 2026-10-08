package control

import "net/http"

// handleConsoleRelays implements GET /console/relays (PROJECT_SPEC section
// 42.2): the read-only peer-relay page. Whether a node serves as a relay, and
// whether a client uses one, are client-local decisions; this page only
// reports what control was told and what the policy authorizes.
func (s *Server) handleConsoleRelays(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "relays")
	if !ok {
		return
	}
	data["View"] = s.relaysView()
	s.renderConsole(w, consoleRelaysTemplate, data)
}
