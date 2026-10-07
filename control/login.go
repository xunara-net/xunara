package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara/xunara/identity"
)

// providerView is a provider as shown on the sign-in page.
type providerView struct {
	ID   string
	Name string
	URL  string
}

// handleLogin implements GET /login.
//
// It starts an AuthTransaction and either redirects to the provider or, for a
// provider that authenticates server-side (the built-in local provider),
// completes the login immediately.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))

	ids := s.providers.IDs()
	if len(ids) == 0 && s.passkeys == nil {
		s.renderError(w, http.StatusServiceUnavailable, "Sign-in unavailable",
			"No identity provider is configured on this server.")
		return
	}

	// An explicit provider must exist: falling back to another provider would
	// silently send the user somewhere they did not choose. A single provider
	// is pre-selected, except when passkey sign-in must be offered too:
	// choosing for the user would hide the passkey button.
	providerID := r.URL.Query().Get("provider")
	if providerID == "" && len(ids) == 1 && s.passkeys == nil {
		providerID = ids[0]
	}
	if providerID == "" {
		views := make([]providerView, 0, len(ids))
		for _, id := range ids {
			views = append(views, providerView{
				ID:   id,
				Name: s.providerName(id),
				URL:  "/login?provider=" + url.QueryEscape(id) + "&return_to=" + url.QueryEscape(returnTo),
			})
		}
		s.renderLoginPage(w, views, s.passkeys != nil)
		return
	}

	provider, ok := s.providers.Get(providerID)
	if !ok {
		s.renderError(w, http.StatusBadRequest, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
	}

	tx, browserSecret, err := s.identity.CreateAuthTransaction(identity.NewAuthTransactionOptions{
		ProviderID:  providerID,
		RedirectURI: s.providerRedirects[providerID],
		ReturnTo:    returnTo,
		TTL:         s.authTTL,
	})
	if err != nil {
		s.log.Error("creating auth transaction", "provider", providerID, "err", err)
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	authReq, err := provider.Begin(r.Context(), &tx)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, loginFailureReason(err))
		s.log.Warn("starting login", "provider", providerID, "err", err)
		s.renderError(w, http.StatusBadGateway, "Provider unavailable",
			"The identity provider could not be reached. Please try again later.")
		return
	}

	if authReq.URL == "" {
		// The provider authenticates server-side (local login): no redirect.
		s.finishLogin(w, r, tx, provider, nil)
		return
	}

	s.setAuthCookie(w, tx.ID, browserSecret, tx.ExpiresAt)
	http.Redirect(w, r, authReq.URL, http.StatusFound)
}

// handleCallback implements GET /oidc/callback/{providerID}.
//
// The provider is taken from the path and cross-checked against the one the
// transaction was created for, so a callback can never be replayed onto a
// different provider.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")

	provider, ok := s.providers.Get(providerID)
	if !ok {
		s.renderError(w, http.StatusNotFound, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
	}

	txID, browserSecret, ok := authCookieValue(r)
	if !ok {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "missing browser binding")
		s.renderError(w, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link is incomplete or has expired. Start again from your device.")
		return
	}

	tx, ok := s.identity.GetAuthTransaction(txID)
	if !ok || tx.ProviderID != providerID {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "unknown transaction")
		s.renderError(w, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link is incomplete or has expired. Start again from your device.")
		return
	}
	// The transaction is bound to the browser that started it: a callback
	// URL stolen from another browser cannot be completed here.
	if !identity.SecretEqual(tx.BrowserSessionHash, browserSecret) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "browser binding mismatch")
		s.renderError(w, http.StatusBadRequest, "Sign-in rejected",
			"This sign-in was started in a different browser. Start again from your device.")
		return
	}
	if tx.Consumed() {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "transaction replayed")
		s.renderError(w, http.StatusBadRequest, "Sign-in already used",
			"This sign-in link has already been used. Start again from your device.")
		return
	}
	if tx.Expired(time.Now()) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "transaction expired")
		s.renderError(w, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link has expired. Start again from your device.")
		return
	}

	query := r.URL.Query()
	s.finishLogin(w, r, tx, provider, &identity.CallbackRequest{
		Code:             query.Get("code"),
		State:            query.Get("state"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
		Values:           query,
	})
}

// finishLogin validates the provider answer, then creates the user (or finds
// it) and a browser session.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, tx identity.AuthTransaction, provider identity.IdentityProvider, cb *identity.CallbackRequest) {
	ctx := r.Context()

	result, err := provider.Callback(ctx, &tx, cb)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), loginFailureReason(err))
		s.log.Warn("login rejected", "provider", provider.ID(), "err", err)
		s.renderError(w, http.StatusForbidden, "Sign-in failed",
			"The identity provider did not confirm this sign-in. Start again from your device.")
		return
	}

	// Redeem the transaction exactly once, after the provider has confirmed
	// the identity: replayed callbacks and reused codes stop here.
	if _, err := s.identity.ConsumeAuthTransaction(tx.ID); err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), loginFailureReason(err))
		s.renderError(w, http.StatusForbidden, "Sign-in failed",
			"This sign-in was already completed. Start again from your device.")
		return
	}

	user, err := s.userForIdentity(result)
	if err != nil {
		s.log.Error("resolving user", "provider", provider.ID(), "err", err)
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), "user resolution failed")
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	session, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: provider.ID(),
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session", "user", int(user.ID), "err", err)
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+provider.ID(), "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+provider.ID())

	s.setSessionCookie(w, token, session.ExpiresAt)
	s.clearAuthCookie(w)

	http.Redirect(w, r, safeReturnTo(tx.ReturnTo), http.StatusFound)
}

// handleLogout implements POST /logout: revoke the session server-side, then
// clear the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := sessionToken(r)
	if token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if err := s.identity.RevokeSession(session.ID, "logout"); err != nil {
		s.log.Error("revoking session", "session", session.ID, "err", err)
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditSessionRevoked, "session:"+session.ID, "logout")

	s.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// userForIdentity maps an authenticated external identity to a user,
// creating one on first login.
//
// Email is an attribute and never a key: an account is only linked to an
// existing user when (provider, subject) matches (AGENTS.md section 6).
func (s *Server) userForIdentity(result *identity.IdentityResult) (identity.User, error) {
	if result == nil || result.ProviderID == "" || result.Subject == "" {
		return identity.User{}, fmt.Errorf("control: incomplete identity result")
	}

	if link, ok := s.identity.GetExternalIdentity(result.ProviderID, result.Subject); ok {
		user, ok := s.identity.GetUser(link.UserID)
		if !ok {
			return identity.User{}, fmt.Errorf("control: external identity (%s, %s) points at missing user %d",
				result.ProviderID, result.Subject, link.UserID)
		}
		if link.Email != result.Email || link.DisplayName != result.DisplayName {
			link.Email, link.DisplayName = result.Email, result.DisplayName
			if err := s.identity.LinkExternalIdentity(&link); err != nil {
				return identity.User{}, err
			}
		}
		if result.Email != "" && user.Email != result.Email {
			user.Email = result.Email
			if err := s.identity.UpdateUser(user); err != nil {
				return identity.User{}, err
			}
		}
		return user, nil
	}

	user := identity.User{
		LoginName:   s.uniqueLoginName(result),
		DisplayName: result.DisplayName,
		Email:       result.Email,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.LoginName
	}
	if err := s.identity.CreateUser(&user); err != nil {
		return identity.User{}, err
	}

	link := identity.ExternalIdentity{
		ProviderID:  result.ProviderID,
		Subject:     result.Subject,
		UserID:      user.ID,
		Email:       result.Email,
		DisplayName: result.DisplayName,
	}
	if err := s.identity.LinkExternalIdentity(&link); err != nil {
		// Do not leave a user nobody can ever log in as.
		if delErr := s.identity.DeleteUser(user.ID); delErr != nil {
			s.log.Error("rolling back user after link failure", "user", int(user.ID), "err", delErr)
		}
		return identity.User{}, err
	}

	s.audit("system", identity.AuditUserCreated, fmt.Sprintf("user:%d", user.ID),
		"created on first login via "+result.ProviderID)
	return user, nil
}

// uniqueLoginName derives a login name from the identity result and makes it
// unique.
func (s *Server) uniqueLoginName(result *identity.IdentityResult) string {
	base := result.Email
	if base == "" {
		base = result.ProviderID + "_" + result.Subject
	}
	base = sanitizeLoginName(base)
	if base == "" {
		base = "user"
	}
	if _, taken := s.identity.GetUserByLoginName(base); !taken {
		return base
	}
	for i := 2; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, taken := s.identity.GetUserByLoginName(candidate); !taken {
			return candidate
		}
	}
	// Practically unreachable; fall back to something unique.
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
}

// sanitizeLoginName keeps login names to characters that are safe in HTML,
// ACL documents and URLs.
func sanitizeLoginName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '@', r == '.', r == '_', r == '-', r == '+':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), ".-_+@")
}

// safeReturnTo only accepts same-origin absolute paths: anything else could
// turn the login endpoint into an open redirect.
func safeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return raw
}

// providerName returns the display name of a provider.
func (s *Server) providerName(id string) string {
	if p, ok := s.providers.Get(id); ok {
		if named, ok := p.(interface{ DisplayName() string }); ok {
			if name := named.DisplayName(); name != "" {
				return name
			}
		}
	}
	return id
}

// loginFailureReason classifies a login failure into a bounded, greppable
// string. Provider-supplied text is never recorded verbatim (it could contain
// tokens or newlines).
func loginFailureReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrStateMismatch):
		return "oauth state mismatch"
	case errors.Is(err, identity.ErrNonceMismatch):
		return "oidc nonce mismatch"
	case errors.Is(err, identity.ErrTokenFromFuture):
		return "id token issued in the future"
	case errors.Is(err, identity.ErrTokenTooOld):
		return "id token too old"
	case errors.Is(err, identity.ErrTransactionExpired):
		return "transaction expired"
	case errors.Is(err, identity.ErrTransactionConsumed):
		return "transaction replayed"
	}
	var pe *identity.ProviderError
	if errors.As(err, &pe) {
		return "provider error: " + sanitizeToken(pe.Code)
	}
	return "callback rejected"
}

// sanitizeToken keeps an identifier to safe characters and a bounded length.
func sanitizeToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
