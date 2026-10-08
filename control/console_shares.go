package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// Xunara Share console (PROJECT_SPEC section 38.3): the operator-facing half
// of cross-organization machine sharing. The page shows the shares this
// organization created (outgoing) and the ones addressed to the signed-in
// user's identities (incoming); the tables never carry addresses or keys.

// consoleShareRow is one share as the console renders it. It embeds the wire
// view so the JSON API and the page agree on every field.
type consoleShareRow struct {
	shareView
	// NodeLabel is the shared machine (or the placeholder for a deleted one).
	NodeLabel string
	// Counterpart is the other organization's display name.
	Counterpart string
	// CanAccept, CanReject and CanRevoke gate the row's buttons.
	CanAccept bool
	CanReject bool
	CanRevoke bool
}

// consoleShareNodeOption is one local machine in the create form's picker.
type consoleShareNodeOption struct {
	Ref   string
	Label string
}

// shareOrgLabel renders one organization for the page: its name when the
// router hosts it, its ID otherwise.
func (s *Server) shareOrgLabel(orgID string) string {
	if orgID == "" {
		return "(none)"
	}
	if orgID == s.Organization().ID {
		if name := s.Organization().Name; name != "" {
			return fmt.Sprintf("%s (%s)", name, orgID)
		}
		return orgID
	}
	if org := s.shareDir.Org(orgID); org != nil {
		if name := org.Organization().Name; name != "" {
			return fmt.Sprintf("%s (%s)", name, orgID)
		}
	}
	return orgID
}

// consoleShareRows renders one direction's shares. canWrite gates the
// outgoing revoke button: withdrawing a share of a machine is administration,
// while a target user may always withdraw their own incoming share.
func (s *Server) consoleShareRows(shares []Share, direction string, canWrite bool) []consoleShareRow {
	rows := make([]consoleShareRow, 0, len(shares))
	for _, share := range shares {
		view := s.shareView(share, direction)
		row := consoleShareRow{
			shareView: view,
			CanRevoke: share.Active(),
		}
		switch {
		case view.Node == nil:
			row.NodeLabel = "(unknown node)"
		case view.Node.Missing:
			row.NodeLabel = fmt.Sprintf("%s (deleted)", view.Node.Hostname)
		default:
			row.NodeLabel = view.Node.Hostname
			if row.NodeLabel == "" {
				row.NodeLabel = view.Node.StableID
			}
		}
		if direction == "outgoing" {
			row.Counterpart = s.shareOrgLabel(share.TargetOrg)
			row.CanRevoke = row.CanRevoke && canWrite
		} else {
			row.Counterpart = s.shareOrgLabel(share.SourceOrg)
			row.CanAccept = share.Status == SharePending
			row.CanReject = share.Status == SharePending
		}
		rows = append(rows, row)
	}
	return rows
}

// consoleShareNodeOptions lists the local machines the create form can share.
func (s *Server) consoleShareNodeOptions() []consoleShareNodeOption {
	nodes := s.store.ListNodes()
	options := make([]consoleShareNodeOption, 0, len(nodes))
	for _, node := range nodes {
		ref := node.StableID
		if ref == "" {
			ref = strconv.FormatUint(uint64(node.ID), 10)
		}
		label := node.Hostname
		if label == "" && node.Hostinfo != nil {
			label = node.Hostinfo.Hostname
		}
		if label == "" {
			label = ref
		}
		if owner := s.userLoginName(node.UserID); owner != "" {
			label += " — " + owner
		}
		options = append(options, consoleShareNodeOption{Ref: ref, Label: label})
	}
	return options
}

// consoleSharesData adds the page's tables to the shared data map.
func (s *Server) consoleSharesData(data map[string]any, principal apiPrincipal) {
	outgoing, err := s.listShares("outgoing", principal)
	if err != nil {
		s.log.Error("listing outgoing shares", "err", err)
		outgoing = nil
	}
	incoming, err := s.listShares("incoming", principal)
	if err != nil {
		s.log.Error("listing incoming shares", "err", err)
		incoming = nil
	}
	canWrite := principal.Role.CanWrite()
	data["Outgoing"] = s.consoleShareRows(outgoing, "outgoing", canWrite)
	data["Incoming"] = s.consoleShareRows(incoming, "incoming", canWrite)
	data["Nodes"] = s.consoleShareNodeOptions()
}

// handleConsoleShares implements GET /console/shares.
func (s *Server) handleConsoleShares(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "shares")
	if !ok {
		return
	}
	data["Enabled"] = s.sharingEnabled()
	if !s.sharingEnabled() {
		// Like Flux, the page explains the disabled feature rather than 404ing.
		s.renderConsole(w, consoleSharesTemplate, data)
		return
	}

	principal, ok := s.sessionPrincipal(session)
	if !ok {
		s.renderError(w, r, http.StatusInternalServerError, "Share unavailable",
			"The signed-in user no longer exists.")
		return
	}
	s.consoleSharesData(data, principal)
	s.renderConsole(w, consoleSharesTemplate, data)
}

// consoleShareError renders a share failure as the console's error page.
func (s *Server) consoleShareError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errShareDisabled):
		s.renderError(w, r, http.StatusNotFound, "Sharing disabled",
			"This deployment has no platform share registry.")
	case errors.Is(err, errShareNodeUnknown):
		s.renderError(w, r, http.StatusNotFound, "Unknown node",
			"No local machine has that ID or stable ID.")
	case errors.Is(err, errShareOrgUnknown):
		s.renderError(w, r, http.StatusNotFound, "Unknown organization",
			"That organization is not hosted by this router.")
	case errors.Is(err, errShareIdentityInvalid):
		s.renderError(w, r, http.StatusBadRequest, "Invalid target identity",
			"Provider and subject are required, and the built-in local provider is not a share target.")
	case errors.Is(err, errShareSelf):
		s.renderError(w, r, http.StatusBadRequest, "Same organization",
			"A machine cannot be shared with its own organization.")
	case errors.Is(err, errShareNotMine):
		s.renderError(w, r, http.StatusNotFound, "Unknown share",
			"No share with that ID belongs to you or your organization.")
	case errors.Is(err, errShareForbidden):
		s.renderError(w, r, http.StatusForbidden, "Not allowed",
			"Your role does not allow withdrawing this share.")
	case errors.Is(err, errShareTKA), errors.Is(err, ErrShareExists), errors.Is(err, errShareDecision):
		s.renderError(w, r, http.StatusConflict, "Share conflict", err.Error())
	default:
		s.log.Error("share action", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Share failed", "Please try again.")
	}
}

// handleConsoleCreateShare implements POST /console/shares.
func (s *Server) handleConsoleCreateShare(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "shares")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}
	if !s.sharingEnabled() {
		s.renderError(w, r, http.StatusNotFound, "Sharing disabled",
			"This deployment has no platform share registry.")
		return
	}
	principal, ok := s.sessionPrincipal(session)
	if !ok {
		s.renderError(w, r, http.StatusUnauthorized, "Session expired", "Sign in again.")
		return
	}

	share, err := s.createShare(r.Context(), principal,
		r.PostFormValue("node"),
		r.PostFormValue("target_organization"),
		r.PostFormValue("provider"),
		r.PostFormValue("subject"),
	)
	if err != nil {
		s.consoleShareError(w, r, err)
		return
	}
	data["Notice"] = fmt.Sprintf("Share %s created; waiting for %s to accept.", share.ID, s.shareOrgLabel(share.TargetOrg))
	data["Enabled"] = true
	s.consoleSharesData(data, principal)
	s.renderConsole(w, consoleSharesTemplate, data)
}

// handleConsoleAcceptShare implements POST /console/shares/{id}/accept.
func (s *Server) handleConsoleAcceptShare(w http.ResponseWriter, r *http.Request) {
	s.consoleShareAction(w, r, s.acceptShare)
}

// handleConsoleRejectShare implements POST /console/shares/{id}/reject.
func (s *Server) handleConsoleRejectShare(w http.ResponseWriter, r *http.Request) {
	s.consoleShareAction(w, r, s.rejectShare)
}

// handleConsoleRevokeShare implements POST /console/shares/{id}/revoke.
func (s *Server) handleConsoleRevokeShare(w http.ResponseWriter, r *http.Request) {
	s.consoleShareAction(w, r, s.revokeShare)
}

// consoleShareAction runs one lifecycle action and re-renders the page.
func (s *Server) consoleShareAction(w http.ResponseWriter, r *http.Request,
	action func(ctx context.Context, actor apiPrincipal, id string) (Share, error)) {
	session, data, ok := s.consoleSession(w, r, "shares")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}
	principal, ok := s.sessionPrincipal(session)
	if !ok {
		s.renderError(w, r, http.StatusUnauthorized, "Session expired", "Sign in again.")
		return
	}

	share, err := action(r.Context(), principal, chi.URLParam(r, "id"))
	if err != nil {
		s.consoleShareError(w, r, err)
		return
	}
	data["Notice"] = fmt.Sprintf("Share %s is now %s.", share.ID, share.Status)
	data["Enabled"] = true
	s.consoleSharesData(data, principal)
	s.renderConsole(w, consoleSharesTemplate, data)
}
