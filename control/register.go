package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/identity"
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
			s.audit(nodeActor(node), identity.AuditNodeDeleted, nodeTarget(node), "client logout")
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

	// 4. Pre-authentication key: the client can be authorized synchronously.
	if req.Auth != nil && req.Auth.AuthKey != "" {
		return s.registerWithAuthKey(req, machineKey)
	}

	// 5. Interactive login: create a pending registration and hand the client a
	//    URL to visit.
	return s.startInteractiveRegistration(req, machineKey)
}

// registerWithAuthKey authorizes a node from a pre-authentication key.
//
// The key authorizes a *machine*; the resulting node is still an independent
// identity. A key is single-use unless it was created reusable.
func (s *Server) registerWithAuthKey(req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	now := time.Now().UTC()

	preauth, ok := s.store.GetPreAuthKey(req.Auth.AuthKey)
	if !ok {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre-auth key", nil)
	}
	if !preauth.Usable(now) {
		return nil, NewHTTPError(http.StatusUnauthorized, "expired or already used pre-auth key", nil)
	}

	var (
		hostname string
		hostinfo *tailcfg.Hostinfo
	)
	if req.Hostinfo != nil {
		hostinfo = req.Hostinfo
		hostname = hostinfo.Hostname
	}

	userID := preauth.UserID
	if userID == 0 {
		userID = state.DefaultUserID
	}

	node := state.Node{
		MachineKey:      machineKey,
		NodeKey:         req.NodeKey,
		UserID:          userID,
		Hostname:        hostname,
		Hostinfo:        hostinfo,
		Method:          state.RegisterMethodAuthKey,
		Ephemeral:       preauth.Ephemeral || req.Ephemeral,
		RequestedExpiry: req.Expiry,
	}
	s.applyRegistrationDefaults(&node, now)

	if err := s.store.CreateNode(&node); err != nil {
		if errors.Is(err, state.ErrNodeKeyExists) {
			return nil, NewHTTPError(http.StatusConflict, "node key already registered", nil)
		}
		return nil, fmt.Errorf("creating node: %w", err)
	}

	// Mark the key used only after the node is durable: a failure between the
	// two must not burn a single-use key without registering a node.
	if err := s.store.MarkPreAuthKeyUsed(preauth.Key, now); err != nil {
		s.log.Warn("marking pre-auth key used", "key_id", preauth.ID, "err", err)
	}

	s.audit(fmt.Sprintf("preauthkey:%d", preauth.ID), identity.AuditNodeRegistered, nodeTarget(node),
		"authorized with a pre-auth key")
	s.notifyWatchers()

	return s.nodeToRegisterResponse(node), nil
}

// nodeActor names a node as an audit actor for machine-initiated events.
func nodeActor(n state.Node) string { return "node:" + n.StableID }

// nodeTarget names a node as an audit target.
func nodeTarget(n state.Node) string { return "node:" + n.StableID }

// nodeToRegisterResponse builds an authorized registration response for a node.
//
// The user and login name come from the trust plane, so a client shows the
// actual human the node belongs to.
func (s *Server) nodeToRegisterResponse(n state.Node) *tailcfg.RegisterResponse {
	profile := s.UserProfile(n.UserID)

	provider := state.DefaultProvider
	if links := s.identity.ListExternalIdentities(n.UserID); len(links) > 0 {
		provider = links[0].ProviderID
	}

	return &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		User: tailcfg.User{
			ID:          n.UserID,
			DisplayName: profile.DisplayName,
			Created:     n.Created,
		},
		Login: tailcfg.Login{
			ID:          tailcfg.LoginID(n.UserID),
			Provider:    provider,
			LoginName:   profile.LoginName,
			DisplayName: profile.DisplayName,
		},
	}
}

// deviceMetadata is the durable description of a pending registration. It
// lives with the device authorization so that any instance can render the
// approval page and create the node without a server-local map.
type deviceMetadata struct {
	Hostname        string            `json:"hostname,omitempty"`
	OS              string            `json:"os,omitempty"`
	Ephemeral       bool              `json:"ephemeral,omitempty"`
	RequestedExpiry time.Time         `json:"requested_expiry,omitempty"`
	Hostinfo        *tailcfg.Hostinfo `json:"hostinfo,omitempty"`
}

// encodeDeviceMetadata serialises the client-provided registration details.
func encodeDeviceMetadata(req tailcfg.RegisterRequest) string {
	meta := deviceMetadata{Ephemeral: req.Ephemeral, RequestedExpiry: req.Expiry}
	if req.Hostinfo != nil {
		meta.Hostname = req.Hostinfo.Hostname
		meta.OS = req.Hostinfo.OS
		meta.Hostinfo = req.Hostinfo
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// decodeDeviceMetadata parses stored metadata, tolerating rows written by
// older builds.
func decodeDeviceMetadata(raw string) deviceMetadata {
	var meta deviceMetadata
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &meta)
	}
	return meta
}

// startInteractiveRegistration creates a pending registration and returns the
// login URL the client should show to the user.
func (s *Server) startInteractiveRegistration(req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	id := newAuthID()
	now := time.Now().UTC()

	// The durable half of the device flow: the approval page and node
	// creation both work from this row, so an approval can be served by any
	// instance.
	if _, err := s.identity.CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		ID:              id,
		MachineKey:      machineKey.String(),
		NodeKey:         req.NodeKey.String(),
		RequestedAction: "register",
		ClientMetadata:  encodeDeviceMetadata(req),
		TTL:             registrationTTL,
	}); err != nil {
		return nil, fmt.Errorf("recording device authorization: %w", err)
	}

	pr := &pendingRegistration{
		id:         id,
		machineKey: machineKey,
		req:        req,
		created:    now,
		done:       make(chan struct{}),
	}

	s.mu.Lock()
	s.pending[pr.id] = pr
	s.pendingByNode[req.NodeKey] = pr.id
	s.mu.Unlock()

	return &tailcfg.RegisterResponse{AuthURL: s.authURL(pr.id)}, nil
}

// waitForFollowup blocks until a pending interactive registration completes.
//
// The in-memory pending registration is only a fast-path wakeup for the
// instance that created it; the durable device authorization decides what the
// client is told, so follow-ups work across instances.
func (s *Server) waitForFollowup(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	s.mu.Lock()
	id, ok := s.pendingByNode[req.NodeKey]
	var pr *pendingRegistration
	if ok {
		pr = s.pending[id]
	}
	s.mu.Unlock()

	if pr != nil && pr.machineKey == machineKey && time.Since(pr.created) <= registrationTTL {
		select {
		case <-pr.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
			return s.nodeToRegisterResponse(node), nil
		}
	}

	if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		return s.nodeToRegisterResponse(node), nil
	}

	if da, ok := s.identity.GetDeviceAuthorizationByNodeKey(req.NodeKey.String()); ok && da.MachineKey == machineKey.String() {
		switch {
		case da.State == identity.DeviceDenied:
			return nil, NewHTTPError(http.StatusForbidden, "registration denied", nil)
		case da.Pending() && !da.Expired(time.Now()):
			// Keep the client polling the same URL: approval may land on any
			// instance and will be visible in the store.
			return &tailcfg.RegisterResponse{AuthURL: s.authURL(da.ID)}, nil
		}
	}

	if pr != nil {
		s.dropPending(pr.id)
	}
	return s.startInteractiveRegistration(req, machineKey)
}

// ApproveRegistration authorizes a pending interactive registration as the
// built-in local user.
//
// This is the seam tests and embedding code call; the web flow uses
// approveDevice with the signed-in user.
func (s *Server) ApproveRegistration(authID string) error {
	_, err := s.approveDevice(authID, state.DefaultUserID, "admin")
	return err
}

// approveDevice authorizes a device and creates its node.
//
// It is idempotent: a retried approval returns success. The node is created
// before the authorization is marked approved, so a crash in between leaves
// the device pending rather than half-approved.
func (s *Server) approveDevice(authID string, userID tailcfg.UserID, actor string) (identity.DeviceAuthorization, error) {
	s.approveMu.Lock()
	defer s.approveMu.Unlock()

	da, ok := s.identity.GetDeviceAuthorization(authID)
	if !ok {
		return identity.DeviceAuthorization{}, NewHTTPError(http.StatusNotFound, "unknown registration", nil)
	}
	now := time.Now().UTC()
	if da.Expired(now) {
		return da, NewHTTPError(http.StatusGone, "registration expired", nil)
	}
	switch da.State {
	case identity.DeviceApproved:
		return da, nil
	case identity.DeviceDenied:
		return da, NewHTTPError(http.StatusConflict, "registration was denied", nil)
	}

	node, err := s.nodeForAuthorization(da, userID, now)
	if err != nil {
		return da, err
	}
	if err := s.store.CreateNode(&node); err != nil && !errors.Is(err, state.ErrNodeKeyExists) {
		return da, fmt.Errorf("creating node: %w", err)
	}

	approved, err := s.identity.ApproveDeviceAuthorization(authID, userID)
	if err != nil {
		return da, fmt.Errorf("approving device: %w", err)
	}

	if stored, ok := s.store.GetNodeByNodeKey(node.NodeKey); ok {
		s.audit(actor, identity.AuditNodeApproved, nodeTarget(stored),
			"approved device registration "+authID)
	}

	s.wakePending(authID)

	// A new node changes every other node's netmap.
	s.notifyWatchers()
	return approved, nil
}

// denyDevice refuses a pending registration.
func (s *Server) denyDevice(authID string, userID tailcfg.UserID, actor string) (identity.DeviceAuthorization, error) {
	s.approveMu.Lock()
	defer s.approveMu.Unlock()

	da, ok := s.identity.GetDeviceAuthorization(authID)
	if !ok {
		return identity.DeviceAuthorization{}, NewHTTPError(http.StatusNotFound, "unknown registration", nil)
	}
	now := time.Now().UTC()
	if da.Expired(now) {
		return da, NewHTTPError(http.StatusGone, "registration expired", nil)
	}
	if da.State == identity.DeviceDenied {
		return da, nil
	}
	if da.State == identity.DeviceApproved {
		return da, NewHTTPError(http.StatusConflict, "registration was already approved", nil)
	}

	denied, err := s.identity.DenyDeviceAuthorization(authID, userID)
	if err != nil {
		return da, fmt.Errorf("denying device: %w", err)
	}
	s.audit(actor, identity.AuditDeviceDenied, "device:"+authID, "denied the device registration")

	s.wakePending(authID)
	return denied, nil
}

// nodeForAuthorization builds the node an approved device authorization
// describes.
func (s *Server) nodeForAuthorization(da identity.DeviceAuthorization, userID tailcfg.UserID, now time.Time) (state.Node, error) {
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(da.MachineKey)); err != nil {
		return state.Node{}, fmt.Errorf("device authorization %s has an invalid machine key: %w", da.ID, err)
	}
	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(da.NodeKey)); err != nil {
		return state.Node{}, fmt.Errorf("device authorization %s has an invalid node key: %w", da.ID, err)
	}

	meta := decodeDeviceMetadata(da.ClientMetadata)
	node := state.Node{
		MachineKey:      machineKey,
		NodeKey:         nodeKey,
		UserID:          userID,
		Hostname:        meta.Hostname,
		Hostinfo:        meta.Hostinfo,
		Method:          state.RegisterMethodInteractive,
		Ephemeral:       meta.Ephemeral,
		RequestedExpiry: meta.RequestedExpiry,
	}
	s.applyRegistrationDefaults(&node, now)
	return node, nil
}

// wakePending wakes the waiter blocked on a pending registration, if this
// instance holds one.
func (s *Server) wakePending(authID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pr, ok := s.pending[authID]
	if !ok {
		return
	}
	delete(s.pending, authID)
	if cur, ok := s.pendingByNode[pr.req.NodeKey]; ok && cur == authID {
		delete(s.pendingByNode, pr.req.NodeKey)
	}
	if !pr.approved {
		pr.approved = true
		close(pr.done)
	}
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

// handleRegisterPage serves the device approval page a user opens from the
// AuthURL the client printed.
func (s *Server) handleRegisterPage(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	da, ok := s.identity.GetDeviceAuthorization(authID)
	if !ok {
		s.renderError(w, http.StatusNotFound, "Unknown login link",
			"This login link is unknown or has expired. Re-run `tailscale up` to get a new one.")
		return
	}
	switch {
	case da.Expired(time.Now()):
		s.renderError(w, http.StatusGone, "Login link expired",
			"This login link has expired. Re-run `tailscale up` to get a new one.")
		return
	case da.State != identity.DevicePending:
		s.renderDecidedPage(w, string(da.State))
		return
	}

	session, ok := s.currentSession(req)
	if !ok {
		http.Redirect(w, req, "/login?return_to="+url.QueryEscape("/register/"+authID), http.StatusFound)
		return
	}

	profile := s.UserProfile(session.UserID)
	meta := decodeDeviceMetadata(da.ClientMetadata)
	hostname := meta.Hostname
	if hostname == "" {
		hostname = "unnamed device"
	}
	os := meta.OS
	if os == "" {
		os = "unknown"
	}

	s.renderApprovePage(w, map[string]any{
		"AuthID":    authID,
		"Hostname":  hostname,
		"OS":        os,
		"Created":   da.CreatedAt.Format(time.RFC3339),
		"LoginName": profile.LoginName,
		"CSRF":      csrfTokenFor(sessionToken(req)),
	})
}

// handleApproveDevice implements POST /register/{authID}/approve.
func (s *Server) handleApproveDevice(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	session, token, ok := s.requireSession(w, req, "/register/"+authID)
	if !ok {
		return
	}
	if !checkCSRF(req, token) {
		s.renderError(w, http.StatusForbidden, "Approval rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	if _, err := s.approveDevice(authID, session.UserID, fmt.Sprintf("user:%d", session.UserID)); err != nil {
		s.renderDeviceError(w, err, "Approval failed")
		return
	}
	s.renderDecidedPage(w, string(identity.DeviceApproved))
}

// handleDenyDevice implements POST /register/{authID}/deny.
func (s *Server) handleDenyDevice(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	session, token, ok := s.requireSession(w, req, "/register/"+authID)
	if !ok {
		return
	}
	if !checkCSRF(req, token) {
		s.renderError(w, http.StatusForbidden, "Denial rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	if _, err := s.denyDevice(authID, session.UserID, fmt.Sprintf("user:%d", session.UserID)); err != nil {
		s.renderDeviceError(w, err, "Denial failed")
		return
	}
	s.renderDecidedPage(w, string(identity.DeviceDenied))
}

// renderDeviceError maps a device approval error to a page.
func (s *Server) renderDeviceError(w http.ResponseWriter, err error, title string) {
	var he HTTPError
	if errors.As(err, &he) {
		s.renderError(w, he.Code, title, he.Msg)
		return
	}
	s.log.Error("device registration failed", "err", err)
	s.renderError(w, http.StatusInternalServerError, title, "Please try again.")
}

// newAuthID returns an unguessable registration identifier.
func newAuthID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("control: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
