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
	"strings"
	"syscall"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/control"
	"github.com/xunara/xunara/identity"
)

func main() {
	var (
		listen       = flag.String("listen", "0.0.0.0:8080", "address to listen on")
		stateDir     = flag.String("state-dir", "data", "directory for persistent state")
		serverURL    = flag.String("server-url", "", "externally reachable base URL (defaults to http://<listen>)")
		domain       = flag.String("domain", "", "tailnet MagicDNS domain (empty disables MagicDNS)")
		derpMapPath  = flag.String("derp-map", "", "path to a tailcfg.DERPMap JSON file to advertise to clients")
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
	)
	var (
		nameservers stringListFlag
		dnsRoutes   stringListFlag
	)
	flag.Var(&nameservers, "nameserver", "global DNS resolver (IP or IP:port); repeatable")
	flag.Var(&dnsRoutes, "dns-route", "split-DNS entry suffix=resolver[,resolver]; repeatable")
	flag.Parse()

	logger := newLogger(*logLevel)

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

	srv, err := control.New(control.Config{
		ServerURL:           *serverURL,
		ListenAddr:          *listen,
		StateDir:            *stateDir,
		Domain:              *domain,
		Nameservers:         nameservers,
		DNSRoutes:           routes,
		PolicyPath:          *policyPath,
		DERPMap:             derpMap,
		LatestClientVersion: *clientVer,
		ClientVersionURL:    *clientVerURL,
		OIDCProviders:       oidcProviders,
		AllowLocalLogin:     *allowLocalLogin,
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
