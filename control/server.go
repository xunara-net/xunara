package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara/xunara/state"
)

// Version is the Xunara server version reported by /version.
const Version = "0.0.0-dev"

// Config configures a [Server].
type Config struct {
	// ServerURL is the externally reachable base URL of this control server,
	// used to build login URLs handed to clients (e.g.
	// "https://login.example.com"). It has no trailing slash.
	ServerURL string
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// StateDir is the directory holding persistent server state.
	StateDir string
	// DBPath is the SQLite database file. It defaults to <StateDir>/state.db.
	DBPath string
	// Domain is the tailnet's MagicDNS domain, without a trailing dot. Empty
	// disables MagicDNS.
	Domain string
	// DERPMap is advertised to clients when non-nil.
	DERPMap *tailcfg.DERPMap
	// Logger receives server logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// Server is the Xunara control plane server.
type Server struct {
	cfg      Config
	log      *slog.Logger
	noiseKey key.MachinePrivate
	store    state.Store
	closer   io.Closer

	// mu guards the registration maps below.
	mu            sync.Mutex
	pending       map[string]*pendingRegistration
	pendingByNode map[key.NodePublic]string

	// sessMu guards control-session bookkeeping and netmap change watchers.
	sessMu        sync.Mutex
	online        map[state.NodeID]int
	watchers      map[uint64]chan struct{}
	nextWatcherID uint64
}

// New builds a Server from cfg, creating the state directory and loading (or
// creating) the server's Noise key.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "data"
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.StateDir, "state.db")
	}

	noiseKey, err := loadOrCreateNoiseKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	store, err := state.OpenSQLite(context.Background(), cfg.DBPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:           cfg,
		log:           cfg.Logger,
		noiseKey:      noiseKey,
		store:         store,
		closer:        store,
		pending:       make(map[string]*pendingRegistration),
		pendingByNode: make(map[key.NodePublic]string),
		online:        make(map[state.NodeID]int),
		watchers:      make(map[uint64]chan struct{}),
	}, nil
}

// Close releases the server's durable resources.
func (s *Server) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// markOnline records that a node holds a control session.
func (s *Server) markOnline(id state.NodeID) {
	s.sessMu.Lock()
	s.online[id]++
	s.sessMu.Unlock()
	s.notifyWatchers()
}

// markOffline releases a control session and records the node's last-seen time.
func (s *Server) markOffline(id state.NodeID) {
	s.sessMu.Lock()
	if n := s.online[id]; n > 1 {
		s.online[id] = n - 1
	} else {
		delete(s.online, id)
	}
	s.sessMu.Unlock()

	if node, ok := s.store.GetNodeByID(id); ok {
		now := time.Now().UTC()
		node.LastSeen = &now
		if err := s.store.UpdateNode(node); err != nil {
			s.log.Warn("recording last seen", "node_id", int(id), "err", err)
		}
	}

	s.notifyWatchers()
}

// isOnline reports whether a node currently holds a control session.
func (s *Server) isOnline(id state.NodeID) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.online[id] > 0
}

// watch registers a netmap change listener. The returned cancel function must
// be called when the listener stops.
func (s *Server) watch() (<-chan struct{}, func()) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	id := s.nextWatcherID
	s.nextWatcherID++

	ch := make(chan struct{}, 1)
	s.watchers[id] = ch

	return ch, func() {
		s.sessMu.Lock()
		defer s.sessMu.Unlock()
		delete(s.watchers, id)
	}
}

// notifyWatchers wakes every netmap change listener. Sends are non-blocking:
// a listener that has not drained its previous notification does not need
// another one.
func (s *Server) notifyWatchers() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for _, ch := range s.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Store returns the tailnet store backing the server.
func (s *Server) Store() state.Store { return s.store }

// NoisePublicKey returns the server's TS2021 Noise public key.
func (s *Server) NoisePublicKey() key.MachinePublic { return s.noiseKey.Public() }

// Handler returns the public HTTP router: the endpoints reachable before a
// Noise session exists.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// TS2021 accepts both the native client's HTTP POST upgrade and the
	// browser/WASM client's WebSocket GET upgrade; the handler dispatches on the
	// Upgrade header, so both methods must reach it.
	r.Get(ts2021UpgradePath, s.handleNoiseUpgrade)
	r.Post(ts2021UpgradePath, s.handleNoiseUpgrade)

	r.Get("/key", s.handleKey)
	r.Get("/health", s.handleHealth)
	r.Get("/version", s.handleVersion)
	r.Get("/register/{authID}", s.handleRegisterPage)
	r.Get("/", s.handleRoot)

	return r
}

// Serve runs the HTTP server until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("control server listening", "addr", s.cfg.ListenAddr, "url", s.cfg.ServerURL)
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
		s.log.Info("control server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// handleKey implements GET /key, returning the server's Noise public key to
// clients at or above the supported capability floor.
func (s *Server) handleKey(w http.ResponseWriter, req *http.Request) {
	capVer, err := parseCapabilityVersion(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if !isSupportedVersion(capVer) {
		httpError(w, NewHTTPError(
			http.StatusBadRequest,
			"unsupported client version",
			errUnsupportedClientVersion,
		))
		return
	}

	writeJSON(w, http.StatusOK, tailcfg.OverTLSPublicKeyResponse{
		PublicKey: s.noiseKey.Public(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "pass"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version":  Version,
		"mine":     "xunara",
		"protocol": "ts2021",
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "Xunara",
		"version": Version,
		"message": "Tailscale-compatible control plane. Point clients at this URL with `tailscale up --login-server=<url>`.",
	})
}
