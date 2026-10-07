package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/policy"
	"github.com/xunara/xunara/state"
)

// consoleDevice is a pending device as shown on the console.
type consoleDevice struct {
	ID       string
	Hostname string
	OS       string
	Created  time.Time
	Expires  time.Time
}

// consoleAuthKey is a pre-auth key as shown on the console. The secret itself
// is deliberately absent: it is displayed exactly once, by the create handler.
type consoleAuthKey struct {
	ID        uint64
	Owner     string
	Reusable  bool
	Ephemeral bool
	Used      bool
	Tags      []string
	Expiry    time.Time
	Created   time.Time
}

// consoleAuthKeyViews renders the key list without secrets.
func (s *Server) consoleAuthKeyViews() []consoleAuthKey {
	keys := s.store.ListPreAuthKeys()
	views := make([]consoleAuthKey, 0, len(keys))
	for _, k := range keys {
		views = append(views, consoleAuthKey{
			ID:        k.ID,
			Owner:     s.UserProfile(k.UserID).LoginName,
			Reusable:  k.Reusable,
			Ephemeral: k.Ephemeral,
			Used:      k.Used,
			Tags:      k.Tags,
			Expiry:    k.Expiry,
			Created:   k.Created,
		})
	}
	return views
}

// splitTagInput splits the console's comma- or whitespace-separated tag field.
func splitTagInput(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// consoleRouter builds the operator console.
func (s *Server) consoleRouter() http.Handler {
	r := chi.NewRouter()

	r.Get("/", s.handleConsoleOverview)

	r.Get("/machines", s.handleConsoleMachines)
	r.Get("/devices", s.handleConsoleDevices)
	r.Get("/users", s.handleConsoleUsers)
	r.Get("/dns", s.handleConsoleDNS)
	r.Get("/auth-keys", s.handleConsoleAuthKeys)
	r.Get("/agents", s.handleConsoleAgents)
	r.Get("/services", s.handleConsoleServices)
	r.Get("/webhooks", s.handleConsoleWebhooks)
	r.Get("/policy", s.handleConsolePolicy)
	r.Get("/audit", s.handleConsoleAudit)
	r.Get("/passkeys", s.handleConsolePasskeys)

	// Passkeys belong to the signed-in user, not to the tailnet, so any role
	// may manage its own; the handlers enforce session + CSRF themselves.
	r.Post("/passkeys/begin", s.handleConsolePasskeyBegin)
	r.Post("/passkeys/finish", s.handleConsolePasskeyFinish)
	r.Post("/passkeys/{id}/delete", s.handleConsoleDeletePasskey)

	// Every write goes through the role guard: members may look at the
	// tailnet, admins and owners may change it.
	r.Group(func(r chi.Router) {
		r.Use(s.consoleWriteAccess)
		r.Post("/machines/{id}/delete", s.handleConsoleDeleteMachine)
		r.Post("/machines/{id}/routes", s.handleConsoleMachineRoutes)
		r.Post("/devices/{id}/approve", s.handleConsoleDevice(true))
		r.Post("/devices/{id}/deny", s.handleConsoleDevice(false))
		r.Post("/users/{id}", s.handleConsoleUpdateUser)
		r.Post("/dns/{id}/delete", s.handleConsoleDeleteDNS)
		r.Post("/auth-keys", s.handleConsoleCreateAuthKey)
		r.Post("/auth-keys/{id}/delete", s.handleConsoleDeleteAuthKey)
		r.Post("/agents/{id}/revoke", s.handleConsoleRevokeAgentToken)
		r.Post("/webhooks", s.handleConsoleCreateWebhook)
		r.Post("/webhooks/{id}/delete", s.handleConsoleDeleteWebhook)
	})

	return r
}

// consoleWriteAccess rejects console writes from read-only roles. Unauthenticated
// requests are sent to the login page, matching the read handlers.
func (s *Server) consoleWriteAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		user, ok := s.identity.GetUser(session.UserID)
		if !ok || !user.Role.CanWrite() {
			s.renderError(w, http.StatusForbidden, "Read-only access",
				"Your role does not allow changing the tailnet.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// consoleSession resolves the session and adds the shared page data.
func (s *Server) consoleSession(w http.ResponseWriter, r *http.Request, nav string) (identity.Session, map[string]any, bool) {
	session, token, ok := s.requireSession(w, r, r.URL.RequestURI())
	if !ok {
		return identity.Session{}, nil, false
	}
	profile := s.UserProfile(session.UserID)
	role := identity.RoleMember
	if user, ok := s.identity.GetUser(session.UserID); ok && user.Role.Valid() {
		role = user.Role
	}
	return session, map[string]any{
		"Nav":       nav,
		"Title":     consoleTitles[nav],
		"User":      profile.LoginName,
		"Role":      role.String(),
		"CanWrite":  role.CanWrite(),
		"IsOwner":   role.IsOwner(),
		"Version":   Version,
		"CSRF":      csrfTokenFor(token),
		"ServerURL": s.cfg.ServerURL,
		"Domain":    s.cfg.Domain,
	}, true
}

// consoleCheckCSRF verifies the form token of a console POST.
func (s *Server) consoleCheckCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !checkCSRF(r, sessionToken(r)) {
		s.renderError(w, http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.")
		return false
	}
	return true
}

// handleConsoleOverview implements GET /console/.
func (s *Server) handleConsoleOverview(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "overview")
	if !ok {
		return
	}

	nodes := s.store.ListNodes()
	online := 0
	for _, n := range nodes {
		if s.isOnline(n.ID) {
			online++
		}
	}
	engine := s.policy.Load()
	policyState := "allow-all (no policy document)"
	if engine != nil {
		policyState = fmt.Sprintf("%d rules", engine.RuleCount())
	}

	data["MachinesTotal"] = len(nodes)
	data["MachinesOnline"] = online
	data["Users"] = len(s.identity.ListUsers())
	data["PendingDevices"] = len(s.identity.ListPendingDeviceAuthorizations(time.Now()))
	data["DNSRecords"] = len(s.store.ListDNSRecords())
	data["AuthKeys"] = len(s.store.ListPreAuthKeys())
	agentTokens := s.identity.ListAgentTokens(0)
	liveAgents := 0
	for _, t := range agentTokens {
		if t.Live(time.Now()) {
			liveAgents++
		}
	}
	data["Agents"] = liveAgents
	data["Policy"] = policyState
	data["TailnetLock"] = s.TKAStatus()
	// The issuer view is best-effort: a keyring an operator must fix (bad
	// permissions, corrupt file) should not blank the whole overview.
	if status, err := s.IDTokenStatus(); err == nil {
		data["IDToken"] = status
	} else {
		data["IDTokenError"] = err.Error()
		s.log.Warn("reading the identity-token issuer state for the console", "err", err)
	}

	s.renderConsole(w, consoleOverviewTemplate, data)
}

// handleConsoleMachines implements GET /console/machines.
func (s *Server) handleConsoleMachines(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}

	nodes := s.store.ListNodes()
	counts := s.deviceAttrCounts()
	serviceCounts := s.serviceCounts()
	machines := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		view := s.apiMachineView(n)
		view.DeviceAttrCount = counts[n.ID]
		view.ServiceCount = serviceCounts[n.ID]
		machines = append(machines, view)
	}
	data["Machines"] = machines
	s.renderConsole(w, consoleMachinesTemplate, data)
}

// handleConsoleDeleteMachine implements POST /console/machines/{id}/delete.
func (s *Server) handleConsoleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, http.StatusNotFound, "Unknown machine", "This machine does not exist.")
		return
	}
	if err := s.store.DeleteNode(node.ID); err != nil {
		s.log.Error("deleting machine", "node", int(node.ID), "err", err)
		s.renderError(w, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditNodeDeleted, nodeTarget(node),
		"deleted through the console")
	s.notifyWatchers()

	data["Notice"] = fmt.Sprintf("Machine %s deleted.", node.Hostname)
	s.handleConsoleMachinesNotice(w, data)
}

// handleConsoleMachinesNotice re-renders the machine list after an action.
func (s *Server) handleConsoleMachinesNotice(w http.ResponseWriter, data map[string]any) {
	nodes := s.store.ListNodes()
	machines := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		machines = append(machines, s.apiMachineView(n))
	}
	data["Machines"] = machines
	s.renderConsole(w, consoleMachinesTemplate, data)
}

// handleConsoleMachineRoutes implements POST /console/machines/{id}/routes.
//
// The form has two actions: approve every announced route, or withdraw every
// approval. Fine-grained approval is available through the API and CLI.
func (s *Server) handleConsoleMachineRoutes(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, http.StatusNotFound, "Unknown machine", "This machine does not exist.")
		return
	}

	var (
		before = node.ApprovedRoutes
		after  []netip.Prefix
		notice string
	)
	switch r.PostFormValue("action") {
	case "approve-all":
		after = state.ApplyRouteApproval(before, node.AnnouncedRoutes(), nil)
		notice = "All announced routes approved."
	case "unapprove-all":
		after = nil
		notice = "All route approvals withdrawn."
	default:
		s.renderError(w, http.StatusBadRequest, "Unknown action", "The form action is not recognised.")
		return
	}

	added, removed := state.RouteDelta(before, after)
	if len(added) == 0 && len(removed) == 0 {
		notice = "No change."
	} else {
		if err := s.store.SetNodeApprovedRoutes(node.ID, after); err != nil {
			s.log.Error("setting approved routes", "node", int(node.ID), "err", err)
			s.renderError(w, http.StatusInternalServerError, "Update failed", "Please try again.")
			return
		}
		if err := s.store.BumpConfigRevision(); err != nil {
			s.log.Error("bumping config revision", "err", err)
		}
		actor := fmt.Sprintf("user:%d", session.UserID)
		for _, p := range added {
			s.audit(actor, identity.AuditRouteApproved, nodeTarget(node), p.String())
		}
		for _, p := range removed {
			s.audit(actor, identity.AuditRouteUnapproved, nodeTarget(node), p.String())
		}
		s.notifyWatchers()
	}

	data["Notice"] = notice
	s.handleConsoleMachinesNotice(w, data)
}

// handleConsoleDevices implements GET /console/devices.
func (s *Server) handleConsoleDevices(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "devices")
	if !ok {
		return
	}

	pending := s.identity.ListPendingDeviceAuthorizations(time.Now())
	devices := make([]consoleDevice, 0, len(pending))
	for _, da := range pending {
		meta := decodeDeviceMetadata(da.ClientMetadata)
		hostname := meta.Hostname
		if hostname == "" {
			hostname = "unnamed device"
		}
		os := meta.OS
		if os == "" {
			os = "unknown"
		}
		devices = append(devices, consoleDevice{
			ID: da.ID, Hostname: hostname, OS: os, Created: da.CreatedAt, Expires: da.ExpiresAt,
		})
	}
	data["Devices"] = devices
	s.renderConsole(w, consoleDevicesTemplate, data)
}

// handleConsoleDevice implements POST /console/devices/{id}/approve|deny.
func (s *Server) handleConsoleDevice(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, data, ok := s.consoleSession(w, r, "devices")
		if !ok {
			return
		}
		if !s.consoleCheckCSRF(w, r) {
			return
		}

		id := chi.URLParam(r, "id")
		actor := fmt.Sprintf("user:%d", session.UserID)

		var err error
		if approve {
			_, err = s.approveDevice(id, session.UserID, actor)
		} else {
			_, err = s.denyDevice(id, session.UserID, actor)
		}
		if err != nil {
			var he HTTPError
			if errors.As(err, &he) {
				s.renderError(w, he.Code, "Device decision failed", he.Msg)
				return
			}
			s.log.Error("deciding device", "device", id, "err", err)
			s.renderError(w, http.StatusInternalServerError, "Device decision failed", "Please try again.")
			return
		}

		if approve {
			data["Notice"] = "Device approved."
		} else {
			data["Notice"] = "Device denied."
		}
		s.handleConsoleDevicesNotice(w, data)
	}
}

// handleConsoleDevicesNotice re-renders the device list after a decision.
func (s *Server) handleConsoleDevicesNotice(w http.ResponseWriter, data map[string]any) {
	pending := s.identity.ListPendingDeviceAuthorizations(time.Now())
	devices := make([]consoleDevice, 0, len(pending))
	for _, da := range pending {
		meta := decodeDeviceMetadata(da.ClientMetadata)
		hostname := meta.Hostname
		if hostname == "" {
			hostname = "unnamed device"
		}
		os := meta.OS
		if os == "" {
			os = "unknown"
		}
		devices = append(devices, consoleDevice{
			ID: da.ID, Hostname: hostname, OS: os, Created: da.CreatedAt, Expires: da.ExpiresAt,
		})
	}
	data["Devices"] = devices
	s.renderConsole(w, consoleDevicesTemplate, data)
}

// handleConsoleUsers implements GET /console/users.
func (s *Server) handleConsoleUsers(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}

	users := s.identity.ListUsers()
	views := make([]apiUser, 0, len(users))
	for _, u := range users {
		views = append(views, s.apiUserView(u))
	}
	data["Users"] = views
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleUpdateUser implements POST /console/users/{id}.
func (s *Server) handleConsoleUpdateUser(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	user, ok := s.lookupAPIUser(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, http.StatusNotFound, "Unknown user", "This user does not exist.")
		return
	}

	var changed []string
	if v := strings.TrimSpace(r.PostFormValue("displayName")); v != "" && v != user.DisplayName {
		user.DisplayName = v
		changed = append(changed, "display_name")
	}
	if v := strings.TrimSpace(r.PostFormValue("email")); v != user.Email {
		user.Email = v
		changed = append(changed, "email")
	}

	roleChanged := false
	if raw := strings.TrimSpace(r.PostFormValue("role")); raw != "" {
		actor, ok := s.identity.GetUser(session.UserID)
		if !ok || !actor.Role.IsOwner() {
			s.renderError(w, http.StatusForbidden, "Owner role required",
				"Only an owner may change roles.")
			return
		}
		role, err := identity.ParseRole(raw)
		if err != nil {
			s.renderError(w, http.StatusBadRequest, "Invalid role", err.Error())
			return
		}
		if role != user.Role {
			if user.Role.IsOwner() && role != identity.RoleOwner && !s.otherOwnerExists(user.ID) {
				s.renderError(w, http.StatusConflict, "Cannot demote the last owner",
					"A tailnet needs at least one owner.")
				return
			}
			user.Role = role
			roleChanged = true
			changed = append(changed, "role")
		}
	}

	if len(changed) == 0 {
		data["Notice"] = "No change."
	} else if err := s.identity.UpdateUser(user); err != nil {
		s.log.Error("updating user", "user", int(user.ID), "err", err)
		s.renderError(w, http.StatusInternalServerError, "Update failed", "Please try again.")
		return
	} else {
		action := identity.AuditUserUpdated
		if roleChanged {
			action = identity.AuditUserRoleChanged
		}
		s.audit(fmt.Sprintf("user:%d", session.UserID), action,
			fmt.Sprintf("user:%d", user.ID), "updated "+strings.Join(changed, ", ")+" through the console")
		data["Notice"] = "User updated."
	}

	s.handleConsoleUsersNotice(w, data)
}

// handleConsoleUsersNotice re-renders the user list after an update.
func (s *Server) handleConsoleUsersNotice(w http.ResponseWriter, data map[string]any) {
	users := s.identity.ListUsers()
	views := make([]apiUser, 0, len(users))
	for _, u := range users {
		views = append(views, s.apiUserView(u))
	}
	data["Users"] = views
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleDNS implements GET /console/dns.
func (s *Server) handleConsoleDNS(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "dns")
	if !ok {
		return
	}
	data["Records"] = s.store.ListDNSRecords()
	s.renderConsole(w, consoleDNSTemplate, data)
}

// handleConsoleDeleteDNS implements POST /console/dns/{id}/delete.
func (s *Server) handleConsoleDeleteDNS(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "dns")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Invalid record", "The record ID is not valid.")
		return
	}

	var record *state.DNSRecord
	for _, rec := range s.store.ListDNSRecords() {
		if rec.ID == id {
			record = &rec
			break
		}
	}
	if record == nil {
		s.renderError(w, http.StatusNotFound, "Unknown record", "This DNS record does not exist.")
		return
	}

	if err := s.store.DeleteDNSRecord(id); err != nil {
		s.log.Error("deleting DNS record", "record", id, "err", err)
		s.renderError(w, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	if err := s.store.BumpConfigRevision(); err != nil {
		s.log.Error("bumping config revision", "err", err)
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditDNSRecordDeleted,
		fmt.Sprintf("dns:%s/%s", record.Name, record.Type), fmt.Sprintf("deleted record %d", record.ID))
	s.notifyWatchers()

	data["Notice"] = "DNS record deleted."
	data["Records"] = s.store.ListDNSRecords()
	s.renderConsole(w, consoleDNSTemplate, data)
}

// handleConsoleAuthKeys implements GET /console/auth-keys.
func (s *Server) handleConsoleAuthKeys(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// handleConsoleCreateAuthKey implements POST /console/auth-keys.
func (s *Server) handleConsoleCreateAuthKey(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		s.log.Error("generating pre-auth key", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}

	key := state.PreAuthKey{
		Key:       secret,
		UserID:    session.UserID,
		Reusable:  r.PostFormValue("reusable") != "",
		Ephemeral: r.PostFormValue("ephemeral") != "",
	}
	tags, err := s.validateKeyTags(splitTagInput(r.PostFormValue("tags")))
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Invalid tags", err.Error())
		return
	}
	key.Tags = tags
	if ttlRaw := strings.TrimSpace(r.PostFormValue("ttl")); ttlRaw != "" {
		ttl, err := time.ParseDuration(ttlRaw)
		if err != nil || ttl <= 0 {
			s.renderError(w, http.StatusBadRequest, "Invalid lifetime", "The key lifetime is not a valid duration.")
			return
		}
		key.Expiry = time.Now().Add(ttl).UTC()
	}
	if err := s.store.CreatePreAuthKey(&key); err != nil {
		s.log.Error("storing pre-auth key", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditPreAuthKeyCreated,
		fmt.Sprintf("preauthkey:%d", key.ID), "created through the console")

	// The secret is shown exactly once.
	data["CreatedKey"] = key.Key
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// handleConsoleDeleteAuthKey implements POST /console/auth-keys/{id}/delete.
func (s *Server) handleConsoleDeleteAuthKey(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Invalid key", "The key ID is not valid.")
		return
	}

	var secret string
	for _, k := range s.store.ListPreAuthKeys() {
		if k.ID == id {
			secret = k.Key
			break
		}
	}
	if secret == "" {
		s.renderError(w, http.StatusNotFound, "Unknown key", "This pre-auth key does not exist.")
		return
	}
	if err := s.store.DeletePreAuthKey(secret); err != nil {
		s.log.Error("deleting pre-auth key", "key", id, "err", err)
		s.renderError(w, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditPreAuthKeyDeleted,
		fmt.Sprintf("preauthkey:%d", id), "deleted through the console")

	data["Notice"] = "Key revoked."
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// consoleAgentTokenViews renders native-client credentials for the console.
func (s *Server) consoleAgentTokenViews() []apiAgentTokenView {
	tokens := s.identity.ListAgentTokens(0)
	out := make([]apiAgentTokenView, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, s.apiAgentTokenView(t))
	}
	return out
}

// handleConsoleServices implements GET /console/services: the read-only
// registry of services nodes advertise about themselves (Xunara Atlas).
func (s *Server) handleConsoleServices(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "services")
	if !ok {
		return
	}

	services := []serviceView{}
	for _, svc := range s.store.ListServices() {
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			continue
		}
		services = append(services, s.serviceView(svc, node))
	}
	data["Services"] = services
	s.renderConsole(w, consoleServicesTemplate, data)
}

// handleConsoleAgents implements GET /console/agents.
func (s *Server) handleConsoleAgents(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "agents")
	if !ok {
		return
	}
	data["Tokens"] = s.consoleAgentTokenViews()
	s.renderConsole(w, consoleAgentsTemplate, data)
}

// handleConsoleRevokeAgentToken implements POST /console/agents/{id}/revoke.
func (s *Server) handleConsoleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "agents")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	var found *identity.AgentToken
	for _, t := range s.identity.ListAgentTokens(0) {
		if t.ID == id {
			token := t
			found = &token
			break
		}
	}
	if found == nil {
		s.renderError(w, http.StatusNotFound, "Unknown credential",
			"This agent credential does not exist.")
		return
	}
	if found.RevokedAt.IsZero() {
		if err := s.identity.RevokeAgentToken(id, time.Now().UTC()); err != nil {
			s.log.Error("revoking agent token", "token", id, "err", err)
			s.renderError(w, http.StatusInternalServerError, "Revoke failed", "Please try again.")
			return
		}
		s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditAgentTokenRevoked,
			"agenttoken:"+id,
			fmt.Sprintf("revoked through the console (node %d)", found.NodeID))
	}

	data["Notice"] = "Agent credential revoked."
	data["Tokens"] = s.consoleAgentTokenViews()
	s.renderConsole(w, consoleAgentsTemplate, data)
}

// consoleWebhookView is a webhook receiver as the console lists it. The
// signing secret is never included (AGENTS.md section 8).
type consoleWebhookView struct {
	ID      string
	URL     string
	Events  []string
	Enabled bool
	Source  string
	Created time.Time
	Updated time.Time
}

// consoleWebhookViews renders both deployment-configured and managed
// receivers; the source tells the operator which ones can be removed at
// runtime.
func (s *Server) consoleWebhookViews() []consoleWebhookView {
	views := make([]consoleWebhookView, 0, len(s.cfg.Webhooks)+4)
	for _, ep := range s.cfg.Webhooks {
		views = append(views, consoleWebhookView{
			ID:      ep.ID,
			URL:     ep.URL,
			Events:  ep.Events,
			Enabled: true,
			Source:  "config",
		})
	}
	for _, managed := range s.identity.ListWebhookEndpoints() {
		views = append(views, consoleWebhookView{
			ID:      managed.ID,
			URL:     managed.URL,
			Events:  managed.Events,
			Enabled: managed.Enabled,
			Source:  "managed",
			Created: managed.CreatedAt,
			Updated: managed.UpdatedAt,
		})
	}
	return views
}

// handleConsoleWebhooks implements GET /console/webhooks.
func (s *Server) handleConsoleWebhooks(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsoleCreateWebhook implements POST /console/webhooks.
func (s *Server) handleConsoleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	endpoint, err := s.normalizeManagedWebhook(
		strings.TrimSpace(r.PostFormValue("id")),
		strings.TrimSpace(r.PostFormValue("url")),
		r.PostFormValue("secret"),
		splitTagInput(r.PostFormValue("events")),
	)
	switch {
	case errors.Is(err, errWebhookIDInvalid):
		s.renderError(w, http.StatusBadRequest, "Invalid webhook ID",
			"The ID must start with a letter or digit and may contain letters, digits, dots, dashes and underscores.")
		return
	case errors.Is(err, errWebhookIDManaged):
		s.renderError(w, http.StatusConflict, "Webhook exists",
			"A managed webhook already uses this ID.")
		return
	case errors.Is(err, errWebhookConfigured):
		s.renderError(w, http.StatusConflict, "Webhook exists",
			"This ID belongs to a webhook configured at startup.")
		return
	case err != nil:
		s.renderError(w, http.StatusBadRequest, "Invalid webhook", err.Error())
		return
	}

	managed, err := s.storeManagedWebhook(endpoint, true)
	if err != nil {
		s.log.Error("creating webhook endpoint", "webhook", endpoint.ID, "err", err)
		s.renderError(w, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditWebhookCreated,
		"webhook:"+managed.ID, "created through the console")

	data["Notice"] = "Webhook created."
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsoleDeleteWebhook implements POST /console/webhooks/{id}/delete.
func (s *Server) handleConsoleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	switch err := s.deleteManagedWebhook(id); {
	case errors.Is(err, errWebhookConfigured):
		s.renderError(w, http.StatusConflict, "Configured webhook",
			"This receiver comes from the server configuration. Remove it there and restart.")
		return
	case errors.Is(err, errWebhookUnknown):
		s.renderError(w, http.StatusNotFound, "Unknown webhook", "This webhook does not exist.")
		return
	case err != nil:
		s.log.Error("deleting webhook endpoint", "webhook", id, "err", err)
		s.renderError(w, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditWebhookDeleted,
		"webhook:"+id, "deleted through the console")

	data["Notice"] = "Webhook deleted."
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsolePolicy implements GET /console/policy.
func (s *Server) handleConsolePolicy(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "policy")
	if !ok {
		return
	}

	engine := s.policy.Load()
	if engine == nil {
		data["Configured"] = false
		s.renderConsole(w, consolePolicyTemplate, data)
		return
	}
	data["Configured"] = true
	data["Path"] = s.cfg.PolicyPath
	data["Rules"] = engine.RuleCount()
	data["Warnings"] = engine.Warnings()
	if doc, err := policy.Load(s.cfg.PolicyPath); err == nil {
		data["Unsupported"] = doc.Unsupported
	} else {
		data["LoadError"] = err.Error()
	}
	s.renderConsole(w, consolePolicyTemplate, data)
}

// handleConsoleAudit implements GET /console/audit.
func (s *Server) handleConsoleAudit(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "audit")
	if !ok {
		return
	}
	// The console shows the newest events first; the store returns the audit
	// log oldest first for streaming consumers.
	events := s.identity.ListAudit(0)
	const consoleAuditLimit = 200
	if len(events) > consoleAuditLimit {
		events = events[len(events)-consoleAuditLimit:]
	}
	slices.Reverse(events)
	data["Events"] = events
	s.renderConsole(w, consoleAuditTemplate, data)
}
