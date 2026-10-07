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
	"syscall"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/control"
)

func main() {
	var (
		listen      = flag.String("listen", "0.0.0.0:8080", "address to listen on")
		stateDir    = flag.String("state-dir", "data", "directory for persistent state")
		serverURL   = flag.String("server-url", "", "externally reachable base URL (defaults to http://<listen>)")
		domain      = flag.String("domain", "", "tailnet MagicDNS domain (empty disables MagicDNS)")
		derpMapPath = flag.String("derp-map", "", "path to a tailcfg.DERPMap JSON file to advertise to clients")
		logLevel    = flag.String("log-level", "info", "log level: debug|info|warn|error")
	)
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

	srv, err := control.New(control.Config{
		ServerURL:  *serverURL,
		ListenAddr: *listen,
		StateDir:   *stateDir,
		Domain:     *domain,
		DERPMap:    derpMap,
		Logger:     logger,
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
