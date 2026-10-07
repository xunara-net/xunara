package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// This file hosts several organizations on one listener. Each organization is
// a full [Server] with its own state store, policy, DNS provider and identity
// store, so tenant isolation is by construction instead of by query filters
// (AGENTS.md section 12). Requests are dispatched by Host: the DNS name a
// client was configured with decides the organization, mirroring how a
// Tailscale login server is per-tailnet.

// OrgSite is one organization hosted by a [Router].
type OrgSite struct {
	// ID is the stable organization identifier, e.g. "acme".
	ID string
	// Name is the human-readable organization name.
	Name string
	// Domains are the request hosts routed to this organization. Entries are
	// exact hosts ("login.acme.example.com") or single-label wildcards
	// ("*.acme.example.com"). Empty is only allowed when the deployment has
	// exactly one site, which then becomes the fallback for every host.
	Domains []string
	// Server is the organization's control plane.
	Server *Server
}

// RouterConfig configures a [Router].
type RouterConfig struct {
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// Orgs are the organizations to serve. At least one is required.
	Orgs []OrgSite
	// PlatformAdminToken authorizes /api/platform/*. It is compared in
	// constant time with the request's bearer token. Empty disables the
	// platform API (fail closed).
	PlatformAdminToken string
	// Logger receives router logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// Router dispatches requests to organizations by Host.
type Router struct {
	cfg  RouterConfig
	log  *slog.Logger
	orgs []*routerOrg

	// fallback is set when exactly one organization exists and declares no
	// domains; it receives every request regardless of Host, preserving
	// single-organization deployments (and tests that use a synthetic host).
	fallback *routerOrg

	// platformTokenHash is the SHA-256 of the platform admin token; hashing
	// equalizes lengths so the constant-time comparison does not leak the
	// token's length.
	platformTokenHash [32]byte

	startOnce sync.Once
}

// routerOrg is an [OrgSite] with its routing state precomputed.
type routerOrg struct {
	site     OrgSite
	patterns []string
	handler  http.Handler
}

// NewRouter validates the organization table and prepares the per-site
// handlers.
func NewRouter(cfg RouterConfig) (*Router, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if len(cfg.Orgs) == 0 {
		return nil, errors.New("control: router needs at least one organization")
	}

	r := &Router{cfg: cfg, log: cfg.Logger}

	seenID := make(map[string]bool, len(cfg.Orgs))
	seenDomain := make(map[string]string, len(cfg.Orgs))
	for _, site := range cfg.Orgs {
		if site.ID == "" {
			return nil, errors.New("control: organization ID is required")
		}
		if site.Server == nil {
			return nil, fmt.Errorf("control: organization %q has no server", site.ID)
		}
		if seenID[site.ID] {
			return nil, fmt.Errorf("control: duplicate organization ID %q", site.ID)
		}
		seenID[site.ID] = true

		org := &routerOrg{site: site, handler: site.Server.Handler()}
		for _, domain := range site.Domains {
			pattern, err := normalizeRouterDomain(domain)
			if err != nil {
				return nil, fmt.Errorf("control: organization %q: %w", site.ID, err)
			}
			if other, dup := seenDomain[pattern]; dup {
				return nil, fmt.Errorf("control: domain %q is claimed by organizations %q and %q",
					pattern, other, site.ID)
			}
			seenDomain[pattern] = site.ID
			org.patterns = append(org.patterns, pattern)
		}
		r.orgs = append(r.orgs, org)
	}

	if len(r.orgs) == 1 && len(r.orgs[0].patterns) == 0 {
		r.fallback = r.orgs[0]
	}
	for _, org := range r.orgs {
		if len(org.patterns) == 0 && org != r.fallback {
			return nil, fmt.Errorf("control: organization %q has no domains and is not the only organization", org.site.ID)
		}
	}

	if cfg.PlatformAdminToken != "" {
		r.platformTokenHash = sha256Sum(cfg.PlatformAdminToken)
	}

	return r, nil
}

// Close releases every organization's durable resources.
func (r *Router) Close() error {
	var errs []error
	for _, org := range r.orgs {
		if err := org.site.Server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", org.site.ID, err))
		}
	}
	return errors.Join(errs...)
}

// Start launches every organization's background workers.
func (r *Router) Start(ctx context.Context) {
	r.startOnce.Do(func() {
		for _, org := range r.orgs {
			org.site.Server.Start(ctx)
		}
	})
}

// Serve runs the HTTP server until ctx is cancelled.
func (r *Router) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              r.cfg.ListenAddr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	r.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		r.log.Info("control server listening",
			"addr", r.cfg.ListenAddr, "organizations", len(r.orgs))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		r.log.Info("control server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Handler returns the router's public HTTP handler.
func (r *Router) Handler() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)

	// Health and version describe the process, not an organization, so they
	// are answered here rather than leaking through a host-specific site.
	mux.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pass"})
	})
	mux.Get("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version":  Version,
			"mine":     "xunara",
			"protocol": "ts2021",
		})
	})

	mux.Route("/api/platform", func(pr chi.Router) {
		r.mountPlatform(pr)
	})

	mux.NotFound(func(w http.ResponseWriter, req *http.Request) {
		org := r.orgForHost(req.Host)
		if org == nil {
			// Do not enumerate organizations on an unknown host.
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unknown organization", http.StatusNotFound)
			return
		}
		org.handler.ServeHTTP(w, req)
	})

	return mux
}

// orgForHost returns the organization a request host belongs to.
func (r *Router) orgForHost(hostport string) *routerOrg {
	host := normalizeRouterHost(hostport)
	if host != "" {
		var best *routerOrg
		bestLen := -1
		for _, org := range r.orgs {
			for _, pattern := range org.patterns {
				if !matchRouterDomain(pattern, host) {
					continue
				}
				// Prefer the most specific (longest) matching pattern so
				// "login.acme.example.com" beats "*.example.com".
				if len(pattern) > bestLen {
					best, bestLen = org, len(pattern)
				}
			}
		}
		if best != nil {
			return best
		}
	}
	return r.fallback
}

// normalizeRouterHost lowercases a Host header value and strips the port and
// any brackets around an IPv6 literal.
func normalizeRouterHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// normalizeRouterDomain validates and canonicalizes one routing domain.
func normalizeRouterDomain(domain string) (string, error) {
	pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if pattern == "" {
		return "", errors.New("empty routing domain")
	}
	if strings.ContainsAny(pattern, " \t\r\n/\\@:") {
		return "", fmt.Errorf("invalid routing domain %q", domain)
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	base := pattern
	if wildcard {
		base = strings.TrimPrefix(pattern, "*.")
		if base == "" {
			return "", fmt.Errorf("invalid routing domain %q", domain)
		}
	}
	if strings.Contains(base, "*") || !strings.Contains(base, ".") {
		return "", fmt.Errorf("invalid routing domain %q", domain)
	}
	return pattern, nil
}

// matchRouterDomain reports whether a canonical host matches a routing domain
// pattern. A "*.example.com" pattern matches exactly one label in front of the
// suffix, matching DNS wildcard semantics.
func matchRouterDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	rest, ok := strings.CutSuffix(host, "."+suffix)
	if !ok || rest == "" {
		return false
	}
	return !strings.Contains(rest, ".")
}
