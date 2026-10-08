package control

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xunara/xunara/identity"
)

// Registration by invitation.
//
// The deployment has no external identity provider, so the only way to create
// an account is an invitation an administrator minted: it is single use,
// expires, and carries the role it grants. There is deliberately no open
// self-registration — a control plane that anyone can join is not a tailnet,
// it is a public network.

const (
	signupRateLimit  = 20
	signupRateWindow = time.Hour
)

// handleSignupPage implements GET /signup.
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This server creates accounts through an identity provider.")
		return
	}
	if s.setupRequired() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	s.renderPublicPage(w, r, signupPageTemplate, map[string]any{
		"Title":     "Create your account",
		"Invite":    strings.TrimSpace(r.URL.Query().Get("invite")),
		"FormToken": s.newFormToken(formPurposeSignup),
	})
}

// handleSignupSubmit implements POST /signup.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This server creates accounts through an identity provider.")
		return
	}
	if s.setupRequired() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	now := time.Now()
	fail := func(status int, title, message string) {
		s.renderError(w, r, status, title, message)
	}

	allowed, retryAfter, err := s.store.AllowRate("signup:"+clientIP(r), signupRateLimit, signupRateWindow, now)
	if err != nil {
		s.log.Error("rate limiting registration", "err", err)
	}
	if err == nil && !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		fail(http.StatusTooManyRequests, "Too many attempts",
			"Too many registration attempts from this address. Try again later.")
		return
	}

	if !s.checkFormToken(formPurposeSignup, r.PostFormValue("_csrf"), now) {
		fail(http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	token := strings.TrimSpace(r.PostFormValue("invite"))
	invite, err := s.identity.FindRegistrationInvite(token)
	switch {
	case errors.Is(err, identity.ErrInviteNotFound):
		s.audit("system", identity.AuditLoginFailed, "signup", "unknown invitation")
		fail(http.StatusForbidden, "Registration rejected",
			"That invitation code is not valid. Ask an administrator for a new link.")
		return
	case errors.Is(err, identity.ErrInviteUsed):
		s.audit("system", identity.AuditLoginFailed, "signup", "invitation already used")
		fail(http.StatusForbidden, "Registration rejected",
			"That invitation has already been used. Ask an administrator for a new link.")
		return
	case errors.Is(err, identity.ErrInviteExpired):
		s.audit("system", identity.AuditLoginFailed, "signup", "invitation expired")
		fail(http.StatusForbidden, "Registration rejected",
			"That invitation has expired. Ask an administrator for a new link.")
		return
	case err != nil:
		s.log.Error("reading invitation", "err", err)
		fail(http.StatusInternalServerError, "Registration failed", "Please try again.")
		return
	}

	login := sanitizeLoginName(r.PostFormValue("login"))
	display := strings.TrimSpace(r.PostFormValue("display_name"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")

	if login == "" {
		fail(http.StatusBadRequest, "Registration rejected",
			"Choose a login name (letters, digits, @ . _ - +).")
		return
	}
	if _, taken := s.identity.GetUserByLoginName(login); taken {
		fail(http.StatusConflict, "Registration rejected", "That login name is already taken.")
		return
	}
	if err := identity.CheckPassword(login, password); err != nil {
		fail(http.StatusBadRequest, "Registration rejected", passwordPolicyMessage(err))
		return
	}
	if password != confirm {
		fail(http.StatusBadRequest, "Registration rejected", "The two passwords do not match.")
		return
	}

	hash, err := identity.HashPassword(password)
	if err != nil {
		s.log.Error("hashing registration password", "err", err)
		fail(http.StatusInternalServerError, "Registration failed", "Please try again.")
		return
	}

	user := identity.User{
		LoginName:   login,
		DisplayName: display,
		Email:       email,
		Role:        invite.Role,
	}
	if user.DisplayName == "" {
		user.DisplayName = login
	}
	if err := s.identity.CreateUser(&user); err != nil {
		s.log.Error("creating registered user", "err", err)
		fail(http.StatusInternalServerError, "Registration failed", "Please try again.")
		return
	}

	// Redeem after the account exists, and roll the account back if the
	// invitation turns out to be gone: an account created by an invitation
	// nobody redeemed must not stay behind.
	if _, err := s.identity.RedeemRegistrationInvite(token, user.ID, now); err != nil {
		if delErr := s.identity.DeleteUser(user.ID); delErr != nil {
			s.log.Error("rolling back registered user", "user", int(user.ID), "err", delErr)
		}
		s.audit("system", identity.AuditLoginFailed, "signup", "invitation could not be redeemed")
		fail(http.StatusConflict, "Registration rejected",
			"That invitation has already been used. Ask an administrator for a new link.")
		return
	}

	if err := s.identity.SetLocalCredential(&identity.LocalCredential{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		s.log.Error("storing registration password", "err", err)
		fail(http.StatusInternalServerError, "Registration failed",
			"The account exists but its password could not be stored. Ask an administrator to reset it.")
		return
	}

	// Local accounts are reachable as the (local, login) external identity,
	// exactly like the built-in administrator, so later features that key on
	// an identity link see them too.
	link := identity.ExternalIdentity{
		ProviderID:  identity.LocalProviderID,
		Subject:     user.LoginName,
		UserID:      user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
	}
	if err := s.identity.LinkExternalIdentity(&link); err != nil {
		s.log.Error("linking registered identity", "user", int(user.ID), "err", err)
	}

	s.audit("system", identity.AuditUserRegistered, fmt.Sprintf("user:%d", user.ID),
		"registered with an invitation as "+string(user.Role))
	s.audit("system", identity.AuditInviteRedeemed, "invite:"+invite.ID, "redeemed by user "+user.LoginName)

	session, sessionToken, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: identity.LocalProviderID,
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session after registration", "err", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)
	s.setSessionCookie(w, sessionToken, session.ExpiresAt)

	http.Redirect(w, r, "/console/", http.StatusFound)
}
