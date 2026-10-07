package control

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/identity"
)

// apiPrincipal is the authenticated caller of a platform API request.
//
// A principal is a human session or a service API key; the machine identity of
// a node is never a principal (AGENTS.md section 5).
type apiPrincipal struct {
	Kind string // "session" or "api_key"

	UserID tailcfg.UserID
	// Role is the acting user's platform role. A service key acts for its
	// owner's role: its scopes narrow that role, they never widen it.
	Role   identity.Role
	Scopes map[string]bool

	Session identity.Session
	APIKey  identity.APIKey
}

// actor names the principal in the audit log.
func (p apiPrincipal) actor() string {
	actor := "user:" + strconv.FormatUint(uint64(p.UserID), 10)
	if p.APIKey.ID != "" {
		actor += "/apikey:" + p.APIKey.ID
	}
	return actor
}

// authenticateAPI resolves the request's credentials: a bearer token (API key
// or session token) or the browser session cookie.
func (s *Server) authenticateAPI(r *http.Request) (apiPrincipal, bool) {
	if raw := r.Header.Get("Authorization"); raw != "" {
		scheme, token, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return apiPrincipal{}, false
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return apiPrincipal{}, false
		}

		if strings.HasPrefix(token, identity.APIKeyPrefix) {
			key, err := s.identity.GetAPIKeyByToken(token)
			if err != nil {
				return apiPrincipal{}, false
			}
			user, ok := s.identity.GetUser(key.UserID)
			if !ok {
				// The owning user is gone; the key is a dangling service
				// identity and must not authenticate.
				return apiPrincipal{}, false
			}
			if err := s.identity.TouchAPIKey(key.ID, time.Now().UTC()); err != nil {
				s.log.Warn("recording API key use", "key", key.ID, "err", err)
			}
			return apiPrincipal{
				Kind:   "api_key",
				UserID: key.UserID,
				Role:   user.Role,
				Scopes: scopeSet(key.Scopes),
				APIKey: key,
			}, true
		}

		if session, err := s.identity.GetSessionByToken(token); err == nil {
			return s.sessionPrincipal(session)
		}
		return apiPrincipal{}, false
	}

	if session, ok := s.currentSession(r); ok {
		return s.sessionPrincipal(session)
	}
	return apiPrincipal{}, false
}

// sessionPrincipal grants a signed-in human the full scope set; the role still
// bounds what those scopes can do.
func (s *Server) sessionPrincipal(session identity.Session) (apiPrincipal, bool) {
	user, ok := s.identity.GetUser(session.UserID)
	if !ok {
		// A session for a deleted user is not a valid principal.
		return apiPrincipal{}, false
	}
	return apiPrincipal{
		Kind:    "session",
		UserID:  session.UserID,
		Role:    user.Role,
		Scopes:  map[string]bool{identity.ScopeRead: true, identity.ScopeWrite: true},
		Session: session,
	}, true
}

// requireScope authenticates the request and checks the scope. The write
// scope additionally requires a role that may change tailnet state; service
// keys inherit their owner's role.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope string) (apiPrincipal, bool) {
	principal, ok := s.authenticateAPI(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="xunara"`)
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return apiPrincipal{}, false
	}
	if !principal.Scopes[scope] {
		writeAPIError(w, http.StatusForbidden, "missing scope: "+scope)
		return apiPrincipal{}, false
	}
	if scope == identity.ScopeWrite && !principal.Role.CanWrite() {
		writeAPIError(w, http.StatusForbidden, "role "+principal.Role.String()+" may not change the tailnet")
		return apiPrincipal{}, false
	}
	return principal, true
}

// requireSelfScope authenticates the request and checks the scope without
// consulting the role: it guards actions a principal may always take on its
// own objects, such as revoking its own session or service key.
func (s *Server) requireSelfScope(w http.ResponseWriter, r *http.Request, scope string) (apiPrincipal, bool) {
	principal, ok := s.authenticateAPI(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="xunara"`)
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return apiPrincipal{}, false
	}
	if !principal.Scopes[scope] {
		writeAPIError(w, http.StatusForbidden, "missing scope: "+scope)
		return apiPrincipal{}, false
	}
	return principal, true
}

// requireOwner authenticates the request and requires the owner role.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) (apiPrincipal, bool) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return apiPrincipal{}, false
	}
	if !principal.Role.IsOwner() {
		writeAPIError(w, http.StatusForbidden, "owner role required")
		return apiPrincipal{}, false
	}
	return principal, true
}

// scopeSet turns a scope list into a lookup set.
func scopeSet(scopes []string) map[string]bool {
	out := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		out[scope] = true
	}
	return out
}

// apiRouter builds the versioned platform API.
func (s *Server) apiRouter() http.Handler {
	r := chi.NewRouter()

	r.Get("/overview", s.handleAPIOverview)

	r.Get("/machines", s.handleAPIMachines)
	r.Get("/machines/{ref}", s.handleAPIMachine)
	r.Delete("/machines/{ref}", s.handleAPIDeleteMachine)
	r.Post("/machines/{ref}/routes", s.handleAPIMachineRoutes)
	r.Get("/routes", s.handleAPIRoutes)

	r.Get("/users", s.handleAPIUsers)
	r.Get("/users/{id}", s.handleAPIUser)
	r.Patch("/users/{id}", s.handleAPIUpdateUser)

	r.Get("/dns", s.handleAPIDNS)
	r.Delete("/dns/{id}", s.handleAPIDeleteDNS)

	r.Get("/policy", s.handleAPIPolicy)

	r.Get("/auth-keys", s.handleAPIAuthKeys)
	r.Post("/auth-keys", s.handleAPICreateAuthKey)
	r.Delete("/auth-keys/{id}", s.handleAPIDeleteAuthKey)

	r.Get("/devices", s.handleAPIDevices)
	r.Post("/devices/{id}/approve", s.handleAPIApproveDevice)
	r.Post("/devices/{id}/deny", s.handleAPIDenyDevice)

	r.Get("/audit", s.handleAPIAudit)

	r.Get("/api-keys", s.handleAPIKeys)
	r.Post("/api-keys", s.handleAPICreateAPIKey)
	r.Delete("/api-keys/{id}", s.handleAPIRevokeAPIKey)

	r.Get("/sessions", s.handleAPISessions)
	r.Delete("/sessions/{id}", s.handleAPIRevokeSession)

	return r
}

// writeAPIError writes a JSON error response.
func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// decodeAPIBody decodes a bounded JSON body, rejecting unknown fields so typos
// are errors instead of silent no-ops.
func decodeAPIBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}
