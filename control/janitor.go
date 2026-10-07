package control

import (
	"context"
	"time"

	"github.com/xunara/xunara/identity"
	"github.com/xunara/xunara/state"
)

// runJanitor periodically reaps ephemeral nodes that have been offline for
// longer than the configured inactivity timeout.
func (s *Server) runJanitor(ctx context.Context) {
	ticker := time.NewTicker(ephemeralReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			s.ReapEphemeral(now)
			s.reapSSHChecks(now)
			s.reapACMEChallenges(now)
			s.reapPasskeyCeremonies(now)
		}
	}
}

// reapACMEChallenges removes DNS-01 challenge records past their TTL, from
// both the internal table and the public zone. Certificate authorities read a
// challenge within minutes; keeping the records for a day leaves ample slack
// for retries without letting them pile up.
func (s *Server) reapACMEChallenges(now time.Time) {
	for _, r := range s.store.ListDNSRecords() {
		if !isACMEChallengeName(r.Name) || r.Type != "TXT" {
			continue
		}
		if now.Sub(r.Created) < certChallengeTTL {
			continue
		}
		if err := s.store.DeleteDNSRecord(r.ID); err != nil {
			s.log.Warn("removing expired ACME challenge record", "record_id", r.ID, "err", err)
			continue
		}
		if s.cfg.DNSProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.cfg.DNSProvider.DeleteTXT(ctx, r.Name); err != nil {
				s.log.Warn("removing ACME challenge from the public zone", "name", r.Name, "err", err)
			}
			cancel()
		}
		s.log.Info("removed expired ACME challenge record", "name", r.Name, "record_id", r.ID)
	}
}

// reapSSHChecks removes SSH check sessions past their TTL.
func (s *Server) reapSSHChecks(now time.Time) {
	deleted, err := s.identity.DeleteExpiredSSHCheckSessions(now)
	if err != nil {
		s.log.Warn("reaping ssh check sessions", "err", err)
		return
	}
	if deleted > 0 {
		s.log.Info("reaped expired ssh check sessions", "count", deleted)
	}
}

// reapPasskeyCeremonies removes WebAuthn challenges past their TTL. A
// ceremony is answered within seconds; keeping the rows for their five-minute
// TTL leaves slack for a slow user gesture without letting challenges pile up.
func (s *Server) reapPasskeyCeremonies(now time.Time) {
	deleted, err := s.identity.DeleteExpiredPasskeyCeremonies(now)
	if err != nil {
		s.log.Warn("reaping passkey ceremonies", "err", err)
		return
	}
	if deleted > 0 {
		s.log.Info("reaped expired passkey ceremonies", "count", deleted)
	}
}

// ReapEphemeral deletes ephemeral nodes that have been offline for at least the
// configured inactivity timeout, and reports how many were removed.
//
// A node that never came online is measured from its creation time, so a
// machine that registers and disappears is still collected.
func (s *Server) ReapEphemeral(now time.Time) int {
	timeout := s.cfg.EphemeralInactivityTimeout
	if timeout <= 0 {
		timeout = DefaultEphemeralInactivityTimeout
	}

	reaped := 0
	for _, n := range s.store.ListNodes() {
		if !n.Ephemeral || s.isOnline(n.ID) {
			continue
		}

		lastActive := n.Created
		if n.LastSeen != nil {
			lastActive = *n.LastSeen
		}
		if now.Sub(lastActive) < timeout {
			continue
		}

		if err := s.store.DeleteNode(n.ID); err != nil {
			s.log.Warn("reaping ephemeral node", "node_id", int(n.ID), "err", err)
			continue
		}
		s.log.Info("reaped ephemeral node", "node_id", int(n.ID), "stable_id", n.StableID)
		s.audit("system", identity.AuditNodeReaped, nodeTarget(n),
			"deleted an ephemeral node that stayed offline past the inactivity timeout")
		reaped++
	}

	if reaped > 0 {
		s.notifyWatchers()
	}
	return reaped
}

// nodeKeyExpiry returns the expiry timestamp to grant a node registering now.
func (s *Server) nodeKeyExpiry(now time.Time) time.Time {
	if s.cfg.NodeKeyExpiry <= 0 {
		return time.Time{}
	}
	return now.Add(s.cfg.NodeKeyExpiry).UTC()
}

// applyRegistrationDefaults fills in the fields every new node shares.
func (s *Server) applyRegistrationDefaults(n *state.Node, now time.Time) {
	// Tagged nodes carry a tag instead of a user identity and never expire:
	// that is the upstream behaviour, and a tagged node can always be
	// re-authorized by whoever owns its tag.
	if len(n.Tags) > 0 {
		n.Expiry = time.Time{}
		return
	}

	n.Expiry = s.nodeKeyExpiry(now)

	// The client may request a shorter expiry than the server default.
	if req := n.RequestedExpiry; !req.IsZero() {
		if n.Expiry.IsZero() || req.Before(n.Expiry) {
			n.Expiry = req.UTC()
		}
	}
}

// configWatchInterval is how often the server checks for configuration changes
// made outside a control session (the administration CLI, or a second server
// instance writing to the same database).
const configWatchInterval = 2 * time.Second

// runConfigWatcher re-pushes the netmap to every connected client whenever the
// store's configuration revision advances.
//
// Node facts learned from a live session wake watchers directly; this covers
// everything that happens out of band. See [state.Store.ConfigRevision].
func (s *Server) runConfigWatcher(ctx context.Context) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()

	last := s.store.ConfigRevision()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rev := s.store.ConfigRevision(); rev != last {
				last = rev
				s.notifyWatchers()
			}
		}
	}
}
