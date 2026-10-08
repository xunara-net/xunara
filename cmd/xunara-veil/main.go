// Command xunara-veil is the Xunara Veil DERP relay server.
//
// It speaks the DERP protocol of the official Tailscale clients and can be
// wired to the control plane's admission endpoint so that only node keys of
// this tailnet are relayed.
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

	"github.com/xunara/xunara/veil"
)

func main() {
	var (
		listen      = flag.String("listen", ":3340", "TCP address for the DERP/HTTP server")
		hostname    = flag.String("hostname", "", "publicly reachable hostname of this node (required with -derp-map-out)")
		stateDir    = flag.String("state-dir", "veil-data", "directory for persistent state (the DERP node key)")
		keyFile     = flag.String("key-file", "", "DERP node key file (default <state-dir>/derp.key)")
		runSTUN     = flag.Bool("stun", true, "run a STUN server for endpoint discovery")
		stunPort    = flag.Int("stun-port", veil.DefaultSTUNPort, "UDP port for STUN")
		verifyURL   = flag.String("verify-url", "", "control plane admission URL (e.g. http://127.0.0.1:8080/derp/admit); empty admits any node key")
		meshKeyEnv  = flag.String("mesh-key-env", "", "environment variable holding the 64-hex DERP mesh key (trusts other Veil nodes); empty disables meshing")
		bandwidth   = flag.Int64("bandwidth-limit", 0, "per-connection bandwidth limit in bytes per second (0: unlimited)")
		bandwidthB  = flag.Int("bandwidth-burst", 0, "token bucket size in bytes for -bandwidth-limit (0: derived from the limit)")
		certFile    = flag.String("cert-file", "", "TLS certificate file (enables TLS with -cert-key-file)")
		certKeyFile = flag.String("cert-key-file", "", "TLS private key file")
		certMode    = flag.String("cert-mode", "", `TLS certificate mode: "manual" (uses -cert-file/-cert-key-file) or "letsencrypt" (ACME via TLS-ALPN-01; requires -hostname and -cert-dir)`)
		certDir     = flag.String("cert-dir", "", "ACME certificate and account cache directory (required with -cert-mode=letsencrypt)")
		acmeEmail   = flag.String("acme-email", "", "contact email for the ACME account (optional)")
		insecure    = flag.Bool("insecure-for-tests", false, "mark the node InsecureForTests in generated DERP maps; local plain-HTTP tests only")
		regionID    = flag.Int("region-id", veil.DefaultRegionID, "DERP region ID in generated maps")
		regionCode  = flag.String("region-code", "veil", "DERP region code in generated maps")
		regionName  = flag.String("region-name", "Xunara Veil", "DERP region name in generated maps")
		derpMapOut  = flag.String("derp-map-out", "", "write a single-node tailcfg.DERPMap JSON here (\"-\" for stdout); pass it to xunarad -derp-map")
		logLevel    = flag.String("log-level", "info", "log level: debug|info|warn|error")
	)
	flag.Parse()

	logger := newLogger(*logLevel)

	// The mesh key is a shared secret: it is read from the environment, never
	// from argv (AGENTS.md section 8). A named-but-empty variable is refused,
	// so a misconfigured deployment cannot silently run without it.
	var meshKey string
	if *meshKeyEnv != "" {
		meshKey = os.Getenv(*meshKeyEnv)
		if meshKey == "" {
			logger.Error("mesh key environment variable is unset or empty", "env", *meshKeyEnv)
			os.Exit(1)
		}
	}

	srv, err := veil.New(veil.Config{
		ListenAddr:       *listen,
		HostName:         *hostname,
		StateDir:         *stateDir,
		KeyFile:          *keyFile,
		STUN:             *runSTUN,
		STUNPort:         *stunPort,
		VerifyURL:        *verifyURL,
		MeshKey:          meshKey,
		BandwidthLimit:   *bandwidth,
		BandwidthBurst:   *bandwidthB,
		CertFile:         *certFile,
		CertKeyFile:      *certKeyFile,
		CertMode:         *certMode,
		CertDir:          *certDir,
		ACMEEmail:        *acmeEmail,
		InsecureForTests: *insecure,
		RegionID:         *regionID,
		RegionCode:       *regionCode,
		RegionName:       *regionName,
		Logger:           logger,
	})
	if err != nil {
		logger.Error("initializing veil", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	if *derpMapOut != "" {
		if err := writeDERPMap(srv, *derpMapOut); err != nil {
			logger.Error("writing DERP map", "err", err)
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		logger.Error("veil error", "err", err)
		os.Exit(1)
	}
}

// writeDERPMap renders the server's single-node DERP map to path, or stdout
// when path is "-".
func writeDERPMap(srv *veil.Server, path string) error {
	m, err := srv.DERPMap()
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	if path == "-" {
		_, err := os.Stdout.Write(blob)
		return err
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
