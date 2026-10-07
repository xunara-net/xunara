package control

// TKAStatus is the read-only administrative view of a tailnet's key authority:
// what operators and automation need to answer "is tailnet lock on, is the
// chain healthy, and how many nodes are actually signed?".
//
// It carries no key material. The head AUM hash and whether a node has a
// signature are public already: every client receives both in the netmap, and
// the whole point of tailnet lock is that peers verify the chain themselves.
type TKAStatus struct {
	// EverEnabled is true once the tailnet had a key authority, even after a
	// disablement, so clients keep receiving TKAInfo until they clear state.
	EverEnabled bool `json:"everEnabled"`
	// Enabled is true while node-key signatures are enforced.
	Enabled bool `json:"enabled"`
	// Disabled is true after the authority was disabled with the support
	// disablement secret; the chain itself is kept.
	Disabled bool `json:"disabled"`
	// Head is the current head AUM hash. Empty unless Enabled.
	Head string `json:"head,omitempty"`
	// Nodes counts the registered nodes and how many carry a node-key
	// signature.
	Nodes TKAStatusNodes `json:"nodes"`
}

// TKAStatusNodes counts signed and unsigned nodes.
//
// A node is "signed" when it carries a stored node-key signature, which is
// what peers require on a locked tailnet; on an unlocked tailnet the count is
// informational (no signature is enforced).
type TKAStatusNodes struct {
	Total    int `json:"total"`
	Signed   int `json:"signed"`
	Unsigned int `json:"unsigned"`
}

// TKAStatus reports the tailnet-lock state of this control plane.
//
// Reads go through the same manager the netmap and the /machine/tka/* RPCs
// use, so the platform surface cannot drift from what clients are told.
func (s *Server) TKAStatus() TKAStatus {
	view := s.tka.view()
	status := TKAStatus{
		EverEnabled: view.EverEnabled,
		Enabled:     view.Enabled,
		Disabled:    view.Disabled,
		Head:        view.Head,
	}
	for _, n := range s.store.ListNodes() {
		status.Nodes.Total++
		if len(n.KeySignature) > 0 {
			status.Nodes.Signed++
		} else {
			status.Nodes.Unsigned++
		}
	}
	return status
}
