package control

import (
	"context"
	"os"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara/xunara/policy"
	"github.com/xunara/xunara/state"
)

// policyWatchInterval is how often the server checks the policy file for
// changes, so an edited ACL takes effect without a restart.
const policyWatchInterval = 2 * time.Second

// loadPolicy reads, parses and compiles the configured policy document,
// replacing the engine the server compiles netmaps from.
//
// A broken document is never applied: the previous policy stays in force and
// the error is returned, because silently falling back to allow-all would open
// the tailnet up.
func (s *Server) loadPolicy() error {
	if s.cfg.PolicyPath == "" {
		return nil
	}

	doc, err := policy.Load(s.cfg.PolicyPath)
	if err != nil {
		return err
	}

	engine, err := policy.NewEngine(doc, policy.Options{
		Domain:    s.cfg.Domain,
		LoginName: userLoginName,
	})
	if err != nil {
		return err
	}

	for _, warning := range engine.Warnings() {
		s.log.Warn("policy", "warning", warning)
	}
	s.log.Info("policy loaded",
		"path", s.cfg.PolicyPath,
		"rules", engine.RuleCount(),
		"unsupported_fields", doc.Unsupported)

	s.policy.Store(engine)
	return nil
}

// runPolicyWatcher reloads the policy file when it changes on disk.
func (s *Server) runPolicyWatcher(ctx context.Context) {
	if s.cfg.PolicyPath == "" {
		return
	}

	ticker := time.NewTicker(policyWatchInterval)
	defer ticker.Stop()

	last := policyModTime(s.cfg.PolicyPath)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mod := policyModTime(s.cfg.PolicyPath)
			if mod.IsZero() || mod.Equal(last) {
				continue
			}
			last = mod

			if err := s.loadPolicy(); err != nil {
				s.log.Error("reloading policy failed; keeping the previous policy",
					"path", s.cfg.PolicyPath, "err", err)
				continue
			}
			s.notifyWatchers()
		}
	}
}

// policyModTime returns the file's modification time, or the zero time when it
// cannot be read.
func policyModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// userLoginName maps a user to the login name ACL selectors are written with.
//
// Until the identity milestone lands every node belongs to a single local
// profile, so this is the profile's login name.
func userLoginName(id tailcfg.UserID) string {
	return state.DefaultUserProfile(id).LoginName
}
