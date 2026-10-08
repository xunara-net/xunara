package control

import "net/http"

// handleConsoleServe implements GET /console/serve (PROJECT_SPEC section
// 43.2): the read-only Serve/Funnel page. Serve itself runs on the node; this
// page shows which devices are authorized, whether certificates are available
// and where Funnel was reported despite not being supported.
func (s *Server) handleConsoleServe(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "serve")
	if !ok {
		return
	}
	data["View"] = s.serveView()
	s.renderConsole(w, consoleServeTemplate, data)
}
