package control

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"

	xunarav2 "github.com/xunara/xunara/api/gen/xunara/v2"
	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

// Platform API v2 over gRPC (M8d).
//
// The gRPC surface mirrors the read-mostly /api/v2 endpoints so automation can
// use a typed protocol; the credentials, scopes, role rules and pagination
// cursors are exactly the HTTP ones. Nothing here touches the Tailscale
// compatibility core: TS2021, Noise, MapRequest and the node/machine key rules
// are unchanged.
//
// One service implementation serves both deployment shapes: a single
// organization registers [Server.RegisterPlatformGRPC], a multi-tenant router
// registers [Router.RegisterPlatformGRPC] and resolves the organization from
// the gRPC authority, which is the HTTP/2 equivalent of the Host header.

// grpcPlatformServer implements xunarav2.PlatformServiceServer. The organization
// is resolved per call, so one registration can serve many organizations.
type grpcPlatformServer struct {
	xunarav2.UnimplementedPlatformServiceServer

	// lookup resolves the organization a call addresses. It returns a gRPC
	// status error when the authority names no organization.
	lookup func(ctx context.Context) (*Server, error)
}

// RegisterPlatformGRPC registers the platform service for this organization.
func (s *Server) RegisterPlatformGRPC(reg grpc.ServiceRegistrar) {
	xunarav2.RegisterPlatformServiceServer(reg, &grpcPlatformServer{
		lookup: func(context.Context) (*Server, error) { return s, nil },
	})
}

// RegisterPlatformGRPC registers the platform service for every organization
// this router serves. The organization is chosen by the gRPC authority
// (":authority"), mirroring HTTP Host routing; an unknown authority is
// reported as NOT_FOUND without listing the hosted organizations.
func (r *Router) RegisterPlatformGRPC(reg grpc.ServiceRegistrar) {
	xunarav2.RegisterPlatformServiceServer(reg, &grpcPlatformServer{
		lookup: func(ctx context.Context) (*Server, error) {
			org := r.orgForHost(grpcAuthority(ctx))
			if org == nil {
				return nil, status.Error(codes.NotFound, "unknown organization")
			}
			return org.site.Server, nil
		},
	})
}

// startPlatformGRPC binds the optional platform gRPC listener for a single
// organization. A disabled surface (no address) returns nil values.
func (s *Server) startPlatformGRPC() (*grpc.Server, net.Listener, error) {
	return startPlatformGRPCOn(s.cfg.GRPCListenAddr, s.RegisterPlatformGRPC)
}

// startPlatformGRPC binds the optional platform gRPC listener for a router.
// Both surfaces are registered on it: the organization-scoped service and the
// deployment-level admin service.
func (r *Router) startPlatformGRPC() (*grpc.Server, net.Listener, error) {
	return startPlatformGRPCOn(r.cfg.GRPCListenAddr, func(reg grpc.ServiceRegistrar) {
		r.RegisterPlatformGRPC(reg)
		r.RegisterPlatformAdminGRPC(reg)
	})
}

// startPlatformGRPCOn binds addr and registers the platform service on it. A
// disabled surface (no address) returns nil values.
func startPlatformGRPCOn(addr string, register func(grpc.ServiceRegistrar)) (*grpc.Server, net.Listener, error) {
	if addr == "" {
		return nil, nil, nil
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("platform gRPC: %w", err)
	}
	srv := grpc.NewServer()
	register(srv)
	return srv, lis, nil
}

// stopPlatformGRPC stops the gRPC server, giving in-flight calls a grace period
// before the hard stop. A nil server is a no-op.
func stopPlatformGRPC(srv *grpc.Server) {
	if srv == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		srv.Stop()
	}
}

// grpcAuthority returns the ":authority" the client addressed, falling back to
// a "host" metadata entry for proxies that rewrite one into the other.
func grpcAuthority(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{":authority", "host"} {
		if values := md.Get(key); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// grpcBearerToken reads the bearer token from the authorization metadata. Only
// the Bearer scheme is accepted, matching the HTTP API.
func grpcBearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	for _, value := range md.Get("authorization") {
		scheme, token, ok := strings.Cut(value, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		if token = strings.TrimSpace(token); token != "" {
			return token, true
		}
	}
	return "", false
}

// authorize resolves the organization and the caller for one call. It applies
// the same credential, scope and role rules as the HTTP API.
func (g *grpcPlatformServer) authorize(ctx context.Context, scope string) (*Server, apiPrincipal, error) {
	server, err := g.lookup(ctx)
	if err != nil {
		return nil, apiPrincipal{}, err
	}

	token, ok := grpcBearerToken(ctx)
	if !ok {
		return nil, apiPrincipal{}, status.Error(codes.Unauthenticated, "authorization metadata with a Bearer token is required")
	}
	principal, ok := server.principalForToken(token)
	if !ok {
		return nil, apiPrincipal{}, status.Error(codes.Unauthenticated, "invalid credential")
	}
	if err := authorizeScope(principal, scope); err != nil {
		return nil, apiPrincipal{}, status.Error(codes.PermissionDenied, err.Error())
	}
	return server, principal, nil
}

// GetMeta implements PlatformService.GetMeta.
func (g *grpcPlatformServer) GetMeta(ctx context.Context, _ *xunarav2.GetMetaRequest) (*xunarav2.Meta, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	return &xunarav2.Meta{
		Version:               Version,
		ServerUrl:             s.cfg.ServerURL,
		Domain:                s.cfg.Domain,
		CapabilityVersion:     uint64(tailcfg.CurrentCapabilityVersion),
		MinCapabilityVersion:  uint64(MinSupportedCapabilityVersion),
		MaxPageSize:           uint32(apiV2MaxPageSize),
		IdentityProviders:     s.providers.IDs(),
		AgentProtocolVersion:  uint32(agentProtocolVersion),
		WebhooksEnabled:       len(s.cfg.Webhooks) > 0,
		DnsProviderConfigured: s.cfg.DNSProvider != nil,
		CertDomains:           slices.Clone(s.certDomains),
		DerpMapConfigured:     s.cfg.DERPMap != nil,
		DerpPolicy:            string(s.cfg.DERPPolicy.Mode),
		DerpRegionsServed:     uint32(s.derpRegionsServed()),
	}, nil
}

// GetTailnetLock implements PlatformService.GetTailnetLock: the same
// read-only tailnet-lock status as GET /api/v2/tka. The AUM chain contents,
// the trusted key material and the sealed disablement secret stay on the
// server; the head hash and node counts are what clients already receive in
// the netmap.
func (g *grpcPlatformServer) GetTailnetLock(ctx context.Context, _ *xunarav2.GetTailnetLockRequest) (*xunarav2.TailnetLockStatus, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	status := s.TKAStatus()
	return &xunarav2.TailnetLockStatus{
		EverEnabled: status.EverEnabled,
		Enabled:     status.Enabled,
		Disabled:    status.Disabled,
		Head:        status.Head,
		Nodes: &xunarav2.TailnetLockNodeCounts{
			Total:    uint32(status.Nodes.Total),
			Signed:   uint32(status.Nodes.Signed),
			Unsigned: uint32(status.Nodes.Unsigned),
		},
	}, nil
}

// ListMachines implements PlatformService.ListMachines. Filters and cursor
// semantics match GET /api/v2/machines.
func (g *grpcPlatformServer) ListMachines(ctx context.Context, req *xunarav2.ListMachinesRequest) (*xunarav2.ListMachinesResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if req.GetState() != "" && req.GetState() != "online" && req.GetState() != "offline" {
		return nil, status.Error(codes.InvalidArgument, "state must be \"online\", \"offline\" or empty")
	}

	limit := grpcPageSize(req.GetPageSize(), 50)
	after, ok := grpcCursorUint(req.GetPageToken(), "machines")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// An unknown user matches nothing instead of being ignored, exactly like
	// the HTTP filter.
	var userFilter uint64
	if raw := strings.TrimSpace(req.GetUser()); raw != "" {
		if id, err := strconv.ParseUint(raw, 10, 64); err == nil {
			userFilter = id
		} else if user, ok := s.identity.GetUserByLoginName(raw); ok {
			userFilter = uint64(user.ID)
		} else {
			userFilter = ^uint64(0)
		}
	}
	tagFilter := strings.TrimSpace(req.GetTag())

	nodes := s.store.ListNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	out := make([]*xunarav2.Machine, 0, limit)
	var last uint64
	next := ""
	for _, n := range nodes {
		id := uint64(n.ID)
		if id <= after {
			continue
		}
		if userFilter != 0 && uint64(n.UserID) != userFilter {
			continue
		}
		if tagFilter != "" && !slices.Contains(n.Tags, tagFilter) {
			continue
		}
		online := s.isOnline(n.ID)
		if req.GetState() == "online" && !online {
			continue
		}
		if req.GetState() == "offline" && online {
			continue
		}
		if len(out) == limit {
			next = apiV2EncodeCursor("machines", strconv.FormatUint(last, 10))
			break
		}
		out = append(out, grpcMachineView(n, s))
		last = id
	}

	return &xunarav2.ListMachinesResponse{Machines: out, NextPageToken: next}, nil
}

// ListAudit implements PlatformService.ListAudit. Filters and cursor semantics
// match GET /api/v2/audit, including the scan bound that keeps a filtered page
// from walking the whole log.
func (g *grpcPlatformServer) ListAudit(ctx context.Context, req *xunarav2.ListAuditRequest) (*xunarav2.ListAuditResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	after, ok := grpcCursorUint(req.GetPageToken(), "audit")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	items := make([]*xunarav2.AuditEvent, 0, limit)
	scanned := 0
	for len(items) < limit && scanned < apiV2AuditScanMax {
		batch := s.identity.ListAuditAfter(after, 256)
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			after = e.ID
			scanned++
			if req.GetAction() != "" && e.Action != req.GetAction() {
				continue
			}
			if req.GetActor() != "" && e.Actor != req.GetActor() {
				continue
			}
			if req.GetTarget() != "" && !strings.HasPrefix(e.Target, req.GetTarget()) {
				continue
			}
			items = append(items, &xunarav2.AuditEvent{
				Id:     e.ID,
				Time:   timestamppb.New(e.Time),
				Actor:  e.Actor,
				Action: e.Action,
				Target: e.Target,
				Detail: e.Detail,
			})
			if len(items) == limit {
				break
			}
		}
		if len(batch) < 256 {
			break
		}
	}

	next := ""
	if len(items) == limit {
		next = apiV2EncodeCursor("audit", strconv.FormatUint(items[len(items)-1].GetId(), 10))
	}
	return &xunarav2.ListAuditResponse{Events: items, NextPageToken: next}, nil
}

// ListWebhooks implements PlatformService.ListWebhooks. The signing secret is
// never returned, matching the HTTP endpoint.
func (g *grpcPlatformServer) ListWebhooks(ctx context.Context, _ *xunarav2.ListWebhooksRequest) (*xunarav2.ListWebhooksResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	views := make([]apiWebhookView, 0, len(s.cfg.Webhooks)+4)
	for _, managed := range s.identity.ListWebhookEndpoints() {
		created, updated := managed.CreatedAt, managed.UpdatedAt
		views = append(views, apiWebhookView{
			ID: managed.ID, URL: managed.URL, Events: managed.Events,
			Enabled: managed.Enabled, Source: "managed",
			CreatedAt: &created, UpdatedAt: &updated,
		})
	}
	for _, ep := range s.cfg.Webhooks {
		views = append(views, apiWebhookView{
			ID: ep.ID, URL: ep.URL, Events: ep.Events, Enabled: true, Source: "config",
		})
	}

	out := make([]*xunarav2.Webhook, 0, len(views))
	for _, view := range views {
		webhook := &xunarav2.Webhook{
			Id:      view.ID,
			Url:     view.URL,
			Events:  slices.Clone(view.Events),
			Enabled: view.Enabled,
			Source:  view.Source,
		}
		if view.CreatedAt != nil {
			webhook.CreatedAt = timestamppb.New(*view.CreatedAt)
		}
		if view.UpdatedAt != nil {
			webhook.UpdatedAt = timestamppb.New(*view.UpdatedAt)
		}
		out = append(out, webhook)
	}
	return &xunarav2.ListWebhooksResponse{Webhooks: out}, nil
}

// RevokeAgentToken implements PlatformService.RevokeAgentToken. It is
// idempotent and audited exactly like DELETE /api/v2/agent-tokens/{id}.
func (g *grpcPlatformServer) RevokeAgentToken(ctx context.Context, req *xunarav2.RevokeAgentTokenRequest) (*xunarav2.RevokeAgentTokenResponse, error) {
	s, principal, err := g.authorize(ctx, identity.ScopeWrite)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "agent token id is required")
	}
	var found *identity.AgentToken
	for _, t := range s.identity.ListAgentTokens(0) {
		if t.ID == id {
			token := t
			found = &token
			break
		}
	}
	if found == nil {
		return nil, status.Error(codes.NotFound, "agent token not found")
	}

	if err := s.identity.RevokeAgentToken(id, time.Now().UTC()); err != nil {
		s.log.Error("revoking agent token", "token", id, "err", err)
		return nil, status.Error(codes.Internal, "could not revoke the agent token")
	}
	s.audit(principal.actor(), identity.AuditAgentTokenRevoked, "agenttoken:"+id,
		fmt.Sprintf("revoked the native client credential of node %d", found.NodeID))
	return &xunarav2.RevokeAgentTokenResponse{Id: id, Revoked: true}, nil
}

// grpcPageSize applies the same page bounds as the HTTP "limit" parameter,
// including that endpoint's default.
func grpcPageSize(requested uint32, def int) int {
	limit := int(requested)
	if limit <= 0 {
		limit = def
	}
	if limit > apiV2MaxPageSize {
		limit = apiV2MaxPageSize
	}
	return limit
}

// grpcCursorUint reads a single-number cursor of the given kind, accepting the
// same opaque tokens the HTTP API returns. An invalid token is rejected rather
// than treated as "from the start".
func grpcCursorUint(raw, kind string) (uint64, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(raw)
	if !ok || (cursorKind != "" && cursorKind != kind) || len(parts) > 1 {
		return 0, false
	}
	if cursorKind == "" {
		return 0, true
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// grpcMachineView builds the typed view of one node.
func grpcMachineView(n state.Node, s *Server) *xunarav2.Machine {
	view := s.apiMachineView(n)
	machine := &xunarav2.Machine{
		Id:              view.ID,
		StableId:        view.StableID,
		Hostname:        view.Hostname,
		UserId:          view.UserID,
		UserLoginName:   view.UserLoginName,
		Online:          view.Online,
		Ephemeral:       view.Ephemeral,
		Expired:         view.Expired,
		Method:          view.Method,
		Ipv4:            view.IPv4,
		Ipv6:            view.IPv6,
		Created:         timestamppb.New(view.Created),
		Tags:            slices.Clone(n.Tags),
		ApprovedRoutes:  slices.Clone(view.ApprovedRoutes),
		AnnouncedRoutes: slices.Clone(view.AnnouncedRoutes),
		ExitNode:        view.ExitNode,
	}
	if view.LastSeen != nil {
		machine.LastSeen = timestamppb.New(*view.LastSeen)
	}
	return machine
}
