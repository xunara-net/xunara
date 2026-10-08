package control

import "net/http"

// handleConsoleExitNodes implements GET /console/exit-nodes (PROJECT_SPEC
// section 40.2): the read-only exit-node page. Approving or withdrawing the
// default route stays on the machines page; this page only reports.
func (s *Server) handleConsoleExitNodes(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "exit-nodes")
	if !ok {
		return
	}
	data["View"] = s.exitNodesView()
	s.renderConsole(w, consoleExitNodesTemplate, data)
}
