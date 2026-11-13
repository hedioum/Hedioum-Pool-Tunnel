package pool

import (
	"errors"
	"log/slog"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// Reverse tunnel: the foreign dials in, so these pools never dial. They are fed with
// AdoptSession, and the foreign redials whenever a pipe retires (lifecycle) or drops.

// RegisterReverseNode provisions the isolated TCP and UDP sub-pools for a node whose
// pipes are dialed by the foreign.
func (hm *HubManager) RegisterReverseNode(cfg config.ForeignNode) {
	hm.RegisterNode(cfg, nil)
}

// AdoptSession hands a pipe that the foreign dialed in to the node's pools. The first
// udpMinConns pipes feed the dedicated UDP sub-pool (so a bulk TCP download cannot
// stall a call, exactly as in forward mode); the rest feed the TCP sub-pool. The hub
// must already be the yamux client on sess (it opens every stream). The session is NOT
// closed on error; the caller owns it.
func (hm *HubManager) AdoptSession(nodeAlias string, sess *yamux.Session, mimicType string) error {
	np, err := hm.lookup(nodeAlias)
	if err != nil {
		return err
	}
	target := np.tcp
	if np.udp.activeCount() < udpMinConns {
		target = np.udp
	}
	return target.adopt(sess, mimicType)
}

// activeCount counts Active sessions under the read lock.
func (np *NodePool) activeCount() int {
	np.mu.RLock()
	defer np.mu.RUnlock()
	return np.activeCountLocked()
}

// adopt wraps a pipe dialed in by the foreign and admits it, applying the same
// admission rules as a dialed pipe: never above maxConnections active, and at the
// total-session cap the oldest draining pipe is evicted to make room.
func (np *NodePool) adopt(sess *yamux.Session, mimicType string) error {
	ws := NewYamuxSession(sess, np.baseLimitMbps, np.jitterMbps, mimicType, np.lifecycle)

	np.mu.Lock()
	defer np.mu.Unlock()
	switch {
	case np.activeCountLocked() >= np.maxConnections:
		return errors.New("pool is at its maximum active connections")
	case len(np.sessions) >= maxTotalFactor*np.maxConnections && !np.evictOldestDrainingLocked():
		return errors.New("pool is at its total connection cap")
	}
	np.sessions = append(np.sessions, ws)
	slog.Info("reverse pipe adopted", "node", np.Alias, "pool", np.label, "mimic", mimicType,
		"active", np.activeCountLocked(), "total", len(np.sessions), "max", np.maxConnections)
	return nil
}
