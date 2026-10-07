package control

import (
	"context"
	"time"

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
			s.ReapEphemeral(time.Now().UTC())
		}
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
	n.Expiry = s.nodeKeyExpiry(now)

	// The client may request a shorter expiry than the server default.
	if req := n.RequestedExpiry; !req.IsZero() {
		if n.Expiry.IsZero() || req.Before(n.Expiry) {
			n.Expiry = req.UTC()
		}
	}
}
