// Command xunarad is the Xunara control plane server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/control"
	"github.com/xunara/xunara/dnsprovider"
	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/webhook"
)

func main() {
	var (
		listen       = flag.String("listen", "0.0.0.0:8080", "address to listen on")
		stateDir     = flag.String("state-dir", "data", "directory for persistent state")
		serverURL    = flag.String("server-url", "", "externally reachable base URL (defaults to http://<listen>)")
		domain       = flag.String("domain", "", "tailnet MagicDNS domain (empty disables MagicDNS)")
		derpMapPath  = flag.String("derp-map", "", "path to a tailcfg.DERPMap JSON file to advertise to clients")
		derpPolicy   = flag.String("derp-policy", "", "DERP policy: empty serves -derp-map, none disables DERP, regions serves only -derp-regions")
		derpRegions  = flag.String("derp-regions", "", "comma-separated DERP region IDs served when -derp-policy=regions")
		clientVer    = flag.String("client-version", "", "latest client version to advertise to clients (e.g. 1.88.3); empty disables the advisory")
		clientVerURL = flag.String("client-version-url", "", "URL opened by the client's update notification (optional)")
		policyPath   = flag.String("policy", "", "path to an ACL policy document (HuJSON); empty allows everything")
		logLevel     = flag.String("log-level", "info", "log level: debug|info|warn|error")
		oidcIssuer   = flag.String("oidc-issuer", "", "OIDC issuer URL; enables OIDC login when set")
		oidcID       = flag.String("oidc-id", "oidc", "provider ID for the OIDC issuer")
		oidcClient   = flag.String("oidc-client-id", "", "OIDC client ID")
		oidcRedirect = flag.String("oidc-redirect-url", "",
			"OIDC redirect URL (default <server-url>/oidc/callback/<oidc-id>)")
		oidcScopes = flag.String("oidc-scopes", "",
			"comma-separated OIDC scopes (default openid,profile,email)")
		allowLocalLogin = flag.Bool("allow-local-login", false,
			"offer the built-in local login even when OIDC is configured")
		passkey = flag.Bool("passkey", true,
			"enable passkey (WebAuthn) sign-in; RP ID and origin default to -server-url")
		passkeyRPID = flag.String("passkey-rpid", "",
			"WebAuthn relying party ID (bare domain, e.g. login.example.com); empty derives it from -server-url")
		passkeyDisplayName = flag.String("passkey-display-name", "",
			"relying party name authenticators show (defaults to the RP ID)")
		dnsWebhook = flag.String("dns-webhook-url", "",
			"HTTPS endpoint that applies DNS record changes for ACME DNS-01 (enables certificates)")
		dnsWebhookTokenEnv = flag.String("dns-webhook-token-env", "XUNARA_DNS_WEBHOOK_TOKEN",
			"environment variable holding the DNS webhook bearer token")
		cfZone     = flag.String("dns-cloudflare-zone", "", "Cloudflare zone for ACME DNS-01 (enables certificates)")
		cfTokenEnv = flag.String("dns-cloudflare-token-env", "XUNARA_CLOUDFLARE_API_TOKEN",
			"environment variable holding the Cloudflare API token")
		orgConfigPath = flag.String("org-config", "",
			"JSON file listing organizations to host (multi-tenant mode; mutually exclusive with the per-organization flags)")
		platformTokenEnv = flag.String("platform-token-env", "XUNARA_PLATFORM_ADMIN_TOKEN",
			"environment variable holding the /api/platform bearer token (multi-tenant mode)")
		grpcListen = flag.String("grpc-listen", "",
			"address for the platform gRPC API (xunara.v2); empty disables gRPC")
		platformStateDir = flag.String("platform-state-dir", "",
			"directory holding the platform registry and platform-managed organizations; empty disables runtime organization CRUD")
		webhookURL = flag.String("webhook-url", "",
			"HTTPS endpoint that receives audit events (enables webhook delivery)")
		webhookSecretEnv = flag.String("webhook-secret-env", "XUNARA_WEBHOOK_SECRET",
			"environment variable holding the webhook HMAC signing secret")
		serviceHealthTTL = flag.Duration("services-health-ttl", control.DefaultServiceHealthTTL,
			"how long a service readiness report stays valid before the service is withdrawn from discovery")
		idTokenRateLimit = flag.Int("id-token-rate-limit", control.DefaultIDTokenRateLimit,
			"identity tokens one node may obtain per audience per minute (0 uses the default)")
		reachEnabled = flag.Bool("reach", false,
			"enable Xunara Reach remote command execution (agents must be re-run with -reach too)")
		fluxEnabled = flag.Bool("flux", false,
			"enable Xunara Flux file transfers between agents (ciphertext is stored under -state-dir)")
		fluxDir = flag.String("flux-dir", "",
			"directory for Flux ciphertext (default <state-dir>/flux)")
		fluxMaxSize = flag.Int64("flux-max-size", 0,
			"Flux plaintext size limit per transfer in bytes (default 8 MiB, hard cap 64 MiB)")
		fluxTTL = flag.Duration("flux-ttl", 0,
			"how long a Flux transfer may stay active (default 1h, max 24h)")
		webhookEvents = flag.String("webhook-events", "",
			"comma-separated audit action globs to deliver (default all events)")
	)
	var (
		nameservers    stringListFlag
		dnsRoutes      stringListFlag
		certDomains    stringListFlag
		passkeyOrigins stringListFlag
	)
	flag.Var(&nameservers, "nameserver", "global DNS resolver (IP or IP:port); repeatable")
	flag.Var(&dnsRoutes, "dns-route", "split-DNS entry suffix=resolver[,resolver]; repeatable")
	flag.Var(&certDomains, "cert-domain", "extra DNS name clients may obtain TLS certificates for; repeatable")
	flag.Var(&passkeyOrigins, "passkey-origin", "allowed WebAuthn origin (repeatable); empty derives it from -server-url")
	flag.Parse()

	logger := newLogger(*logLevel)

	// Multi-tenant mode routes by Host and takes every organization-level
	// setting from the config file, so mixing in the single-tenant flags would
	// be ambiguous. Refuse instead of guessing.
	if *orgConfigPath != "" {
		if err := rejectOrgScopedFlags(); err != nil {
			logger.Error("invalid configuration", "err", err)
			os.Exit(1)
		}
		runRouter(*orgConfigPath, *listen, *grpcListen, *platformTokenEnv, *platformStateDir, logger)
		return
	}
	if *platformStateDir != "" {
		logger.Error("-platform-state-dir requires -org-config (platform-managed organizations are a multi-tenant feature)")
		os.Exit(1)
	}

	if *serverURL == "" {
		*serverURL = "http://" + *listen
	}

	derpMap, err := loadDERPMap(*derpMapPath)
	if err != nil {
		logger.Error("loading DERP map", "err", err)
		os.Exit(1)
	}

	routes, err := parseDNSRouteFlags(dnsRoutes)
	if err != nil {
		logger.Error("parsing -dns-route", "err", err)
		os.Exit(1)
	}

	dnsProvider, err := buildDNSProvider(*dnsWebhook, *dnsWebhookTokenEnv, *cfZone, *cfTokenEnv)
	if err != nil {
		logger.Error("configuring the DNS provider", "err", err)
		os.Exit(1)
	}

	// The client secret is read from the environment, never from a flag:
	// process arguments are visible to every user on the host.
	var oidcProviders []identity.OIDCConfig
	if *oidcIssuer != "" {
		oidcProviders = append(oidcProviders, identity.OIDCConfig{
			ID:          *oidcID,
			DisplayName: *oidcID,
			Issuer:      *oidcIssuer,
			ClientID:    *oidcClient,
			// XUNARA_OIDC_CLIENT_SECRET keeps the secret out of argv.
			ClientSecret: os.Getenv("XUNARA_OIDC_CLIENT_SECRET"),
			RedirectURL:  *oidcRedirect,
			Scopes:       splitCSV(*oidcScopes),
		})
	}

	var webhooks []webhook.Endpoint
	if *webhookURL != "" {
		secret := os.Getenv(*webhookSecretEnv)
		if secret == "" {
			logger.Error("webhook delivery needs a signing secret", "env", *webhookSecretEnv)
			os.Exit(1)
		}
		webhooks = append(webhooks, webhook.Endpoint{
			ID:     "default",
			URL:    *webhookURL,
			Secret: secret,
			Events: splitCSV(*webhookEvents),
		})
	}

	derpPolicyValue, err := control.ParseDERPPolicy(*derpPolicy, *derpRegions)
	if err != nil {
		logger.Error("parsing the DERP policy", "err", err)
		os.Exit(1)
	}

	passkeyCfg, err := buildPasskeyConfig(*passkey, *serverURL, *passkeyRPID, *passkeyDisplayName, passkeyOrigins)
	if err != nil {
		logger.Error("invalid passkey configuration", "err", err)
		os.Exit(1)
	}
	if *passkey && passkeyCfg == nil {
		logger.Warn("passkey sign-in is disabled: -server-url cannot serve as a WebAuthn relying party (use -passkey-rpid/-passkey-origin, or -passkey=false to silence this)")
	}

	fluxCfg, err := fluxConfigFor(*fluxEnabled, *fluxDir, *fluxMaxSize, *fluxTTL)
	if err != nil {
		logger.Error("invalid flux configuration", "err", err)
		os.Exit(1)
	}

	srv, err := control.New(control.Config{
		ServerURL:           *serverURL,
		ListenAddr:          *listen,
		GRPCListenAddr:      *grpcListen,
		StateDir:            *stateDir,
		Domain:              *domain,
		Nameservers:         nameservers,
		DNSRoutes:           routes,
		PolicyPath:          *policyPath,
		DERPMap:             derpMap,
		DERPPolicy:          derpPolicyValue,
		LatestClientVersion: *clientVer,
		ClientVersionURL:    *clientVerURL,
		OIDCProviders:       oidcProviders,
		AllowLocalLogin:     *allowLocalLogin,
		Passkeys:            passkeyCfg,
		CertDomains:         certDomains,
		DNSProvider:         dnsProvider,
		ServiceHealthTTL:    *serviceHealthTTL,
		IDTokenRateLimit:    *idTokenRateLimit,
		ReachEnabled:        *reachEnabled,
		Flux:                fluxCfg,
		Webhooks:            webhooks,
		Logger:              logger,
	})
	if err != nil {
		logger.Error("initializing server", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// orgScopedFlags are the flags that describe a single organization. They are
// rejected in -org-config mode, where the config file owns them.
var orgScopedFlags = []string{
	"state-dir", "server-url", "domain", "policy", "nameserver", "dns-route",
	"derp-map", "derp-policy", "derp-regions", "client-version", "client-version-url",
	"oidc-issuer", "oidc-id", "oidc-client-id", "oidc-redirect-url", "oidc-scopes",
	"allow-local-login", "cert-domain",
	"passkey", "passkey-rpid", "passkey-origin", "passkey-display-name",
	"services-health-ttl", "id-token-rate-limit", "reach",
	"flux", "flux-dir", "flux-max-size", "flux-ttl",
	"dns-webhook-url", "dns-webhook-token-env",
	"dns-cloudflare-zone", "dns-cloudflare-token-env",
	"webhook-url", "webhook-secret-env", "webhook-events",
}

// rejectOrgScopedFlags fails when the operator combined -org-config with a
// flag that belongs to the single-organization configuration.
func rejectOrgScopedFlags() error {
	var visited []string
	flag.Visit(func(f *flag.Flag) { visited = append(visited, f.Name) })
	return checkOrgScopedFlags(visited)
}

// checkOrgScopedFlags is the pure part of [rejectOrgScopedFlags].
func checkOrgScopedFlags(visited []string) error {
	var offending []string
	for _, name := range visited {
		for _, scoped := range orgScopedFlags {
			if name == scoped {
				offending = append(offending, "-"+name)
			}
		}
	}
	if len(offending) == 0 {
		return nil
	}
	return fmt.Errorf("-org-config cannot be combined with %s; move them into the config file",
		strings.Join(offending, ", "))
}

// runRouter serves a multi-tenant deployment until the process is signalled.
// When platformStateDir is set, the platform API may also create and delete
// organizations at runtime; their control planes live under that directory.
func runRouter(path, listen, grpcListen, platformTokenEnv, platformStateDir string, logger *slog.Logger) {
	sites, err := loadOrgSites(path, logger)
	if err != nil {
		logger.Error("loading the organization table", "err", err)
		os.Exit(1)
	}

	platformToken := os.Getenv(platformTokenEnv)
	if platformToken == "" {
		logger.Warn("platform API disabled: environment variable is empty",
			"env", platformTokenEnv)
	}

	var registry *control.OrgRegistry
	if platformStateDir != "" {
		if platformToken == "" {
			logger.Error("platform-managed organizations need a platform token",
				"env", platformTokenEnv)
			os.Exit(1)
		}
		registry, err = control.OpenOrgRegistry(context.Background(), control.OrgRegistryConfig{
			Path:      filepath.Join(platformStateDir, "platform.db"),
			StateRoot: filepath.Join(platformStateDir, "orgs"),
			// Managed organizations inherit the deployment's process-level
			// settings (the logger and nothing that carries a secret).
			NewServer: func(org control.ManagedOrg, stateDir string) (*control.Server, error) {
				return control.New(control.Config{
					ServerURL: org.ServerURL,
					Domain:    org.Domain,
					StateDir:  stateDir,
					Logger:    logger,
				})
			},
		})
		if err != nil {
			logger.Error("opening the platform organization registry", "err", err)
			os.Exit(1)
		}
	}

	router, err := control.NewRouter(control.RouterConfig{
		ListenAddr:         listen,
		GRPCListenAddr:     grpcListen,
		Orgs:               sites,
		PlatformAdminToken: platformToken,
		Registry:           registry,
		Logger:             logger,
	})
	if err != nil {
		for _, site := range sites {
			_ = site.Server.Close()
		}
		if registry != nil {
			_ = registry.Close()
		}
		logger.Error("initializing the organization router", "err", err)
		os.Exit(1)
	}
	defer router.Close()

	for _, site := range sites {
		logger.Info("organization hosted",
			"id", site.ID, "name", site.Name, "domains", strings.Join(site.Domains, ","))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := router.Serve(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// buildDNSProvider assembles the external DNS writer for ACME DNS-01 from
// flags. API tokens are read from the environment: process arguments are
// visible to every user on the host (AGENTS.md section 8).
func buildDNSProvider(webhookURL, webhookTokenEnv, cfZone, cfTokenEnv string) (control.DNSProvider, error) {
	switch {
	case webhookURL != "" && cfZone != "":
		return nil, fmt.Errorf("configure either -dns-webhook-url or -dns-cloudflare-zone, not both")
	case webhookURL != "":
		return dnsprovider.NewWebhook(webhookURL, os.Getenv(webhookTokenEnv))
	case cfZone != "":
		token := os.Getenv(cfTokenEnv)
		if token == "" {
			return nil, fmt.Errorf("dnsprovider: set %s to the Cloudflare API token", cfTokenEnv)
		}
		return dnsprovider.NewCloudflare(cfZone, token)
	}
	return nil, nil
}

// stringListFlag collects a repeatable string flag.
type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// parseDNSRouteFlags turns "suffix=resolver[,resolver]" entries into the map
// control.Config expects.
func parseDNSRouteFlags(entries []string) (map[string][]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	out := make(map[string][]string, len(entries))
	for _, entry := range entries {
		suffix, resolvers, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not of the form suffix=resolver[,resolver]", entry)
		}
		suffix = strings.TrimSpace(suffix)
		if suffix == "" {
			return nil, fmt.Errorf("%q has an empty suffix", entry)
		}

		var list []string
		for _, r := range strings.Split(resolvers, ",") {
			if r = strings.TrimSpace(r); r != "" {
				list = append(list, r)
			}
		}
		out[suffix] = list
	}
	return out, nil
}

// loadDERPMap reads a tailcfg.DERPMap JSON document, returning nil when no path
// is configured.
func loadDERPMap(path string) (*tailcfg.DERPMap, error) {
	if path == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m tailcfg.DERPMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &m, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// splitCSV splits a comma-separated flag value, dropping empty entries.
func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
