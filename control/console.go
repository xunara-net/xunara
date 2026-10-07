package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
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
	r.Post("/machines/{id}/delete", s.handleConsoleDeleteMachine)
	r.Post("/machines/{id}/routes", s.handleConsoleMachineRoutes)

	r.Get("/devices", s.handleConsoleDevices)
	r.Post("/devices/{id}/approve", s.handleConsoleDevice(true))
	r.Post("/devices/{id}/deny", s.handleConsoleDevice(false))

	r.Get("/users", s.handleConsoleUsers)
	r.Post("/users/{id}", s.handleConsoleUpdateUser)

	r.Get("/dns", s.handleConsoleDNS)
	r.Post("/dns/{id}/delete", s.handleConsoleDeleteDNS)

	r.Get("/auth-keys", s.handleConsoleAuthKeys)
	r.Post("/auth-keys", s.handleConsoleCreateAuthKey)
	r.Post("/auth-keys/{id}/delete", s.handleConsoleDeleteAuthKey)

	r.Get("/policy", s.handleConsolePolicy)
	r.Get("/audit", s.handleConsoleAudit)

	return r
}

// consoleSession resolves the session and adds the shared page data.
func (s *Server) consoleSession(w http.ResponseWriter, r *http.Request, nav string) (identity.Session, map[string]any, bool) {
	session, token, ok := s.requireSession(w, r, r.URL.RequestURI())
	if !ok {
		return identity.Session{}, nil, false
	}
	profile := s.UserProfile(session.UserID)
	return session, map[string]any{
		"Nav":       nav,
		"Title":     consoleTitles[nav],
		"User":      profile.LoginName,
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
	data["Policy"] = policyState

	s.renderConsole(w, consoleOverviewTemplate, data)
}

// handleConsoleMachines implements GET /console/machines.
func (s *Server) handleConsoleMachines(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}

	nodes := s.store.ListNodes()
	machines := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		machines = append(machines, s.apiMachineView(n))
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

	if len(changed) == 0 {
		data["Notice"] = "No change."
	} else if err := s.identity.UpdateUser(user); err != nil {
		s.log.Error("updating user", "user", int(user.ID), "err", err)
		s.renderError(w, http.StatusInternalServerError, "Update failed", "Please try again.")
		return
	} else {
		s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditUserUpdated,
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
