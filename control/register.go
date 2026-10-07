package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/state"
)

// registrationTTL bounds how long an interactive registration may stay pending
// before a follow-up restarts it.
const registrationTTL = 10 * time.Minute

// pendingRegistration tracks a node that is mid interactive login. It is
// deliberately separate from node state and from any future session: an
// authorization transaction is not a session (AGENTS.md section 10).
type pendingRegistration struct {
	id         string
	machineKey key.MachinePublic
	req        tailcfg.RegisterRequest
	created    time.Time

	done     chan struct{}
	approved bool
}

// handleRegister implements POST /machine/register inside a Noise session.
func (ns *noiseServer) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		httpError(w, NewHTTPError(http.StatusMethodNotAllowed, "method not allowed", nil))
		return
	}

	var registerRequest tailcfg.RegisterRequest
	decodeErr := json.NewDecoder(req.Body).Decode(&registerRequest)

	// Enforce the version floor even when the body failed to decode: whatever
	// version was read is what is checked.
	if ns.rejectUnsupported(w, registerRequest.Version, registerRequest.NodeKey) {
		return
	}

	resp := func() *tailcfg.RegisterResponse {
		if decodeErr != nil {
			return &tailcfg.RegisterResponse{Error: decodeErr.Error()}
		}

		out, err := ns.server.handleRegister(req.Context(), registerRequest, ns.machineKey)
		if err != nil {
			var he HTTPError
			if errors.As(err, &he) {
				return &tailcfg.RegisterResponse{Error: he.Msg}
			}
			return &tailcfg.RegisterResponse{Error: err.Error()}
		}
		return out
	}()

	writeJSON(w, http.StatusOK, resp)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// handleRegister is the transport-independent registration decision.
func (s *Server) handleRegister(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	// 1. Logout: a request whose expiry is in the past is a logout, regardless
	//    of any other field. It takes precedence over an auth key.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
			if node.MachineKey != machineKey {
				return nil, NewHTTPError(http.StatusUnauthorized,
					"machine key does not match node", nil)
			}
			if err := s.store.DeleteNode(node.ID); err != nil {
				return nil, fmt.Errorf("deleting logged-out node: %w", err)
			}
		}
		return &tailcfg.RegisterResponse{}, nil
	}

	// 2. Known node: re-registration after a client restart. The machine key
	//    from the Noise session must match the stored one, otherwise a holder of
	//    the node key could impersonate the machine.
	if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		if node.MachineKey != machineKey {
			return nil, NewHTTPError(http.StatusUnauthorized,
				"machine key does not match existing node key", nil)
		}
		return s.nodeToRegisterResponse(node), nil
	}

	// 3. Follow-up: the client already started a login and is polling for the
	//    result.
	if req.Followup != "" {
		return s.waitForFollowup(ctx, req, machineKey)
	}

	// 4. Interactive login: create a pending registration and hand the client a
	//    URL to visit.
	return s.startInteractiveRegistration(req, machineKey)
}

// nodeToRegisterResponse builds an authorized registration response for a node.
func (s *Server) nodeToRegisterResponse(n state.Node) *tailcfg.RegisterResponse {
	return &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		User:              state.DefaultUser(n.UserID, n.Created),
		Login: tailcfg.Login{
			ID:        tailcfg.LoginID(n.UserID),
			Provider:  state.DefaultProvider,
			LoginName: state.DefaultLoginName,
		},
	}
}

// startInteractiveRegistration creates a pending registration and returns the
// login URL the client should show to the user.
func (s *Server) startInteractiveRegistration(req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	pr := &pendingRegistration{
		id:         newAuthID(),
		machineKey: machineKey,
		req:        req,
		created:    time.Now().UTC(),
		done:       make(chan struct{}),
	}

	s.mu.Lock()
	s.pending[pr.id] = pr
	s.pendingByNode[req.NodeKey] = pr.id
	s.mu.Unlock()

	return &tailcfg.RegisterResponse{AuthURL: s.authURL(pr.id)}, nil
}

// waitForFollowup blocks until a pending interactive registration completes.
func (s *Server) waitForFollowup(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	s.mu.Lock()
	id, ok := s.pendingByNode[req.NodeKey]
	var pr *pendingRegistration
	if ok {
		pr = s.pending[id]
	}
	s.mu.Unlock()

	if pr == nil || pr.machineKey != machineKey || time.Since(pr.created) > registrationTTL {
		if pr != nil {
			s.dropPending(pr.id)
		}
		return s.startInteractiveRegistration(req, machineKey)
	}

	select {
	case <-pr.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		return s.nodeToRegisterResponse(node), nil
	}
	// Not approved yet (e.g. re-signalled): tell the client to keep waiting.
	return &tailcfg.RegisterResponse{AuthURL: s.authURL(pr.id)}, nil
}

// ApproveRegistration authorizes a pending interactive registration, creating
// the node.
//
// This is the seam the admin/Web flow will call at a later milestone; today it
// is exercised directly by tests. It never trusts anything but the server-side
// pending record: the machine key stored at request time is what gets bound to
// the node.
func (s *Server) ApproveRegistration(authID string) error {
	s.mu.Lock()
	pr, ok := s.pending[authID]
	s.mu.Unlock()
	if !ok {
		return NewHTTPError(http.StatusNotFound, "unknown registration", nil)
	}
	if time.Since(pr.created) > registrationTTL {
		s.dropPending(authID)
		return NewHTTPError(http.StatusGone, "registration expired", nil)
	}
	if pr.approved {
		return nil
	}

	var (
		hostname string
		hostinfo *tailcfg.Hostinfo
	)
	if pr.req.Hostinfo != nil {
		hostinfo = pr.req.Hostinfo
		hostname = hostinfo.Hostname
	}

	node := state.Node{
		MachineKey: pr.machineKey,
		NodeKey:    pr.req.NodeKey,
		UserID:     state.DefaultUserID,
		Hostname:   hostname,
		Hostinfo:   hostinfo,
		Method:     state.RegisterMethodInteractive,
		Ephemeral:  pr.req.Ephemeral,
	}

	if err := s.store.CreateNode(&node); err != nil && !errors.Is(err, state.ErrNodeKeyExists) {
		return fmt.Errorf("creating node: %w", err)
	}

	s.mu.Lock()
	pr.approved = true
	s.mu.Unlock()
	close(pr.done)

	// A new node changes every other node's netmap.
	s.notifyWatchers()

	return nil
}

// dropPending removes a pending registration from the index.
func (s *Server) dropPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr, ok := s.pending[id]
	if !ok {
		return
	}
	delete(s.pending, id)
	if cur, ok := s.pendingByNode[pr.req.NodeKey]; ok && cur == id {
		delete(s.pendingByNode, pr.req.NodeKey)
	}
}

func (s *Server) authURL(authID string) string {
	return fmt.Sprintf("%s/register/%s", s.cfg.ServerURL, authID)
}

// handleRegisterPage serves the login landing page a user opens from the
// AuthURL the client printed.
func (s *Server) handleRegisterPage(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	s.mu.Lock()
	pr, ok := s.pending[authID]
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ok {
		http.Error(w, "This login link is unknown or has expired. Re-run `tailscale up` to get a new one.", http.StatusNotFound)
		return
	}

	status := "pending approval"
	if pr.approved {
		status = "approved"
	}
	fmt.Fprintf(w, "Xunara login\n\nregistration: %s\nstatus: %s\ncreated: %s\n\nApproval is not yet wired to the web UI in this milestone.\n",
		authID, status, pr.created.Format(time.RFC3339))
}

// newAuthID returns an unguessable registration identifier.
func newAuthID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("control: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
