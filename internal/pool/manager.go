package pool

import (
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

const (
	defaultMaxConns = 15
	defaultMinConns = 10
	staggerDelay    = 500 * time.Millisecond
	healthCheckFreq = 10 * time.Second

	// Draining grace: an actively-transferring pipe (a live download/call) is never
	// force-closed before the hard ceiling — new traffic already uses fresh pipes,
	// so the retiring pipe just finishes its existing streams. Only an empty or idle
	// pipe closes quickly; the hard ceiling is a final backstop against a stream that
	// lingers forever (which would otherwise leak file descriptors).
	drainSoftGrace   = 90 * time.Second
	drainHardCeiling = 30 * time.Minute
	// maxTotalFactor caps total sessions (active + draining) at this multiple of
	// maxConnections, so draining pipes can never grow unbounded. Kept tight (2×) so
	// the connection count to one egress IP stays modest (traffic-analysis stealth).
	// At the cap, a fresh active pipe evicts the oldest drainer rather than starving.
	maxTotalFactor = 2
)

// shouldCloseDraining decides whether a draining pipe may be closed now. It never
// cuts an actively-transferring stream before the hard ceiling: a clean pipe (no
// streams) closes immediately, an idle one after a short grace, and any pipe at the
// hard ceiling. This is what lets a user's in-flight download/call finish on its
// (retiring) pipe while all new traffic seamlessly moves to fresh pipes.
func shouldCloseDraining(streams int, drainedFor time.Duration, idle bool) bool {
	if streams == 0 {
		return true
	}
	if idle && drainedFor > drainSoftGrace {
		return true
	}
	return drainedFor > drainHardCeiling
}

// DialFunc creates a new authenticated physical connection and reports which mimic
// type it used, so the pool can apply the protocol-aware retirement policy.
type DialFunc func() (*yamux.Session, string, error)

// PoolStats holds real-time telemetry data for the interactive dashboard.
type PoolStats struct {
	ActiveConns   int
	DrainingConns int
	TotalMbps     int
}

// NodePool manages an auto-scaling pool of Yamux sessions to a single foreign server.
type NodePool struct {
	Alias          string
	label          string // "tcp" or "udp" — which sub-pool, for observability in logs
	TargetIP       string
	minConnections int
	maxConnections int
	baseLimitMbps  int
	jitterMbps     int
	dialer         DialFunc
	lifecycle      LifecyclePolicy
	sessions       []*YamuxSession
	mu             sync.RWMutex
	currentMbps    int32 // Atomic total bandwidth of this pool for dashboard monitoring
	shutdown       chan struct{}
}

// UDP sub-pool sizing. UDP rides a SEPARATE set of (still SSH-masked TCP)
// physical connections so a bulk TCP download cannot head-of-line-block a
// real-time UDP call. Kept small and hidden from user config.
const (
	udpMinConns = 2
	udpMaxConns = 6
)

// nodePools holds the two isolated sub-pools for one foreign node. Both dial the
// same egress over the identical masked TCP transport; they differ only in which
// logical streams (TCP CONNECT vs UDP ASSOCIATE) ride them.
type nodePools struct {
	tcp *NodePool
	udp *NodePool
}

// HubManager oversees all active foreign node pools in the Iran Hub.
type HubManager struct {
	pools map[string]*nodePools
	mu    sync.RWMutex
}

// NewHubManager initializes the global pool manager for the Iran relay node.
func NewHubManager() *HubManager {
	return &HubManager{
		pools: make(map[string]*nodePools),
	}
}

// newNodePool builds and starts a monitored connection pool.
func newNodePool(cfg config.ForeignNode, label string, minConns, maxConns int, dialer DialFunc, lifecycle LifecyclePolicy) *NodePool {
	pool := &NodePool{
		Alias:          cfg.Alias,
		label:          label,
		TargetIP:       cfg.TargetIP,
		minConnections: minConns,
		maxConnections: maxConns,
		baseLimitMbps:  cfg.BandwidthLimitMbps,
		jitterMbps:     cfg.BandwidthJitterMbps,
		dialer:         dialer,
		lifecycle:      lifecycle,
		sessions:       make([]*YamuxSession, 0, maxConns),
		shutdown:       make(chan struct{}),
	}
	go pool.monitorAndScale() // dedicated watchdog for this pool
	return pool
}

// RegisterNode provisions the isolated TCP and UDP sub-pools for a foreign server.
func (hm *HubManager) RegisterNode(cfg config.ForeignNode, dialer DialFunc) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	minConns := cfg.MinConnections
	if minConns < 1 {
		minConns = defaultMinConns
	}
	maxConns := cfg.MaxConnections
	if maxConns < minConns {
		maxConns = minConns + 5 // Ensure max is always reasonably higher than min
	}

	// Per-server lifecycle personality, seeded from this node's secret auth token:
	// each server churns with different aggregate statistics, unguessable from outside.
	lifecycle := NewLifecyclePolicy(cfg.AuthToken)

	hm.pools[cfg.Alias] = &nodePools{
		tcp: newNodePool(cfg, "tcp", minConns, maxConns, dialer, lifecycle),
		udp: newNodePool(cfg, "udp", udpMinConns, udpMaxConns, dialer, lifecycle),
	}
}

// GetStreamTCP returns a least-loaded stream on the node's TCP sub-pool.
func (hm *HubManager) GetStreamTCP(nodeAlias string) (net.Conn, error) {
	np, err := hm.lookup(nodeAlias)
	if err != nil {
		return nil, err
	}
	return np.tcp.getStreamLeastLoaded()
}

// GetStreamUDP returns a least-loaded stream on the node's dedicated UDP sub-pool.
func (hm *HubManager) GetStreamUDP(nodeAlias string) (net.Conn, error) {
	np, err := hm.lookup(nodeAlias)
	if err != nil {
		return nil, err
	}
	return np.udp.getStreamLeastLoaded()
}

func (hm *HubManager) lookup(nodeAlias string) (*nodePools, error) {
	hm.mu.RLock()
	np, exists := hm.pools[nodeAlias]
	hm.mu.RUnlock()
	if !exists {
		return nil, errors.New("foreign node pool not found")
	}
	return np, nil
}

// getStreamLeastLoaded routes the new logical stream to the active physical connection handling the fewest streams.
func (np *NodePool) getStreamLeastLoaded() (net.Conn, error) {
	np.mu.RLock()
	defer np.mu.RUnlock()

	var bestSession *YamuxSession
	minStreams := int(^uint(0) >> 1) // Max Int value

	for _, s := range np.sessions {
		// Do not route new traffic to dead or draining connections
		if s.IsClosed() || s.IsDraining() {
			continue
		}

		activeStreams := s.ActiveStreams()
		if activeStreams < minStreams {
			minStreams = activeStreams
			bestSession = s
		}
	}

	if bestSession == nil {
		return nil, errors.New("no active connections available in the pool")
	}

	return bestSession.OpenStream()
}

// monitorAndScale is the core watchdog evaluating bandwidth, Chaos evasion, and scale dynamics.
func (np *NodePool) monitorAndScale() {
	ticker := time.NewTicker(healthCheckFreq)
	defer ticker.Stop()

	// Initial warmup based on dynamic MinConnections
	np.replenishPool(np.minConnections)

	for {
		select {
		case <-np.shutdown:
			np.cleanup()
			return
		case <-ticker.C:
			np.evaluateHealthAndScale()
		}
	}
}

// evaluateHealthAndScale calculates throughput, shifts DPI evasion caps, and executes Scale-Up/Down logic.
func (np *NodePool) evaluateHealthAndScale() {
	np.mu.Lock()
	var retainedSessions []*YamuxSession

	dynamicIdleLimit := time.Duration(rand.Intn(61)+60) * time.Second
	needsScaleUp := false
	activeCount := 0
	totalPoolMbps := 0

	// 1. Analyze all sessions
	for _, s := range np.sessions {
		if s.IsClosed() {
			slog.Info("purged dead physical connection", "node", np.Alias, "pool", np.label)
			continue
		}

		// Calculate bandwidth (Mbps) over the last check interval
		bytesLastInterval := s.GetAndResetBytes()
		intervalSeconds := uint64(healthCheckFreq.Seconds())
		mbps := int((bytesLastInterval * 8) / (1024 * 1024 * intervalSeconds))
		totalPoolMbps += mbps

		// Randomize speed limits to evade pattern matching (and update Token Bucket)
		s.UpdateChaosLimit()
		cap := s.CurrentCap()

		if s.IsActive() {
			activeCount++

			// Protocol-aware retirement (the dominant stealth property): a pipe past
			// its randomized lifetime / transfer budget is drained UNCONDITIONALLY —
			// even at the minimum pool size — so the pool churns to a fresh pipe with
			// a new random mimic. The min-connection guarantee below immediately
			// replaces it. SSH rotates on a long (hours) schedule; every other mimic
			// churns fast (minutes / a few GB). Independent random per-connection
			// timers keep retirements staggered, never all at once.
			if s.ShouldRetire() {
				s.SetDraining()
				activeCount--
				slog.Info("retired: lifecycle budget reached", "node", np.Alias, "pool", np.label,
					"mimic", s.mimicType, "age", s.Age().Round(time.Second), "mb", s.CumulativeBytes()/(1024*1024))
			} else {
				// Scale-Up trigger: If this connection is pushing beyond 80% of its Chaos Cap
				if mbps >= int(float64(cap)*0.8) {
					needsScaleUp = true
				}

				// Scale-Down logic: Drop excess connections that are barely moving traffic
				if activeCount > np.minConnections && mbps < 1 && s.IdleTime() > dynamicIdleLimit {
					s.SetDraining() // Shift to Draining (Wait for logical streams to drop to zero)
					activeCount--
					slog.Info("scaled down: connection draining (idle/low load)", "node", np.Alias, "pool", np.label)
				}
			}
		} else if s.IsDraining() {
			// Close a draining pipe only when it is safe: empty, idle-past-grace, or at
			// the hard ceiling. An active transfer keeps flowing on its pipe until it
			// finishes — we never cut a live download/call to satisfy retirement.
			streams := s.ActiveStreams()
			drainedFor := s.DrainingFor()
			if shouldCloseDraining(streams, drainedFor, mbps < 1) {
				s.Close()
				slog.Info("draining complete: connection closed", "node", np.Alias, "pool", np.label,
					"streams", streams, "drained_for", drainedFor.Round(time.Second))
				continue // Remove from memory
			}
		}

		retainedSessions = append(retainedSessions, s)
	}

	np.sessions = retainedSessions
	atomic.StoreInt32(&np.currentMbps, int32(totalPoolMbps))
	np.mu.Unlock()

	// 2. Execute Scale-Up if triggered by heavy load
	if needsScaleUp {
		np.executeScaleUp()
	}

	// 3. Guarantee baseline availability based on ACTIVE connections only. Draining
	// pipes are "on their way out" and never block replenishment — this is what keeps
	// the pool from starving when retiring pipes are slow to drain (issue #23).
	np.mu.RLock()
	currentActive := np.activeCountLocked()
	np.mu.RUnlock()

	// Watchdog: a node with zero active pipes is a starved pool — surface it and
	// re-warm immediately (the replenish below does the actual healing).
	if currentActive == 0 && np.dialer != nil {
		slog.Warn("watchdog: pool has no active connections — re-warming", "node", np.Alias, "pool", np.label)
	}
	if currentActive < np.minConnections {
		np.replenishPool(np.minConnections - currentActive)
	}
}

// activeCountLocked counts Active (non-draining, non-closed) sessions. Caller holds np.mu.
func (np *NodePool) activeCountLocked() int {
	n := 0
	for _, s := range np.sessions {
		if s.IsActive() {
			n++
		}
	}
	return n
}

// evictOldestDrainingLocked force-closes and removes the pipe that has been draining
// the longest, to free a slot for a fresh active pipe at the total-session cap.
// Returns false if there is no draining pipe to evict. Caller holds np.mu.
func (np *NodePool) evictOldestDrainingLocked() bool {
	idx := -1
	var oldest time.Duration
	for i, s := range np.sessions {
		if s.IsDraining() {
			if d := s.DrainingFor(); idx == -1 || d > oldest {
				idx, oldest = i, d
			}
		}
	}
	if idx == -1 {
		return false
	}
	np.sessions[idx].Close()
	slog.Info("evicted oldest draining connection to free a slot", "node", np.Alias, "pool", np.label,
		"drained_for", oldest.Round(time.Second))
	np.sessions = append(np.sessions[:idx], np.sessions[idx+1:]...)
	return true
}

// executeScaleUp dials a fresh physical connection under load. Draining is terminal:
// a pipe that started draining is never brought back — reviving a lifecycle-retired
// pipe would just re-retire it (churn for nothing), and always dialing fresh keeps
// the mimic mix rotating, which is the point. Gated on the ACTIVE count so draining
// pipes never block scale-up.
func (np *NodePool) executeScaleUp() {
	np.mu.RLock()
	activeConns := np.activeCountLocked()
	np.mu.RUnlock()

	if activeConns < np.maxConnections {
		np.replenishPool(1)
	} else {
		slog.Warn("max active connections reached", "node", np.Alias, "pool", np.label, "max", np.maxConnections)
	}
}

func (np *NodePool) replenishPool(needed int) {
	if np.dialer == nil {
		return // reverse-tunnel pool: the foreign dials in (see reverse.go)
	}
	for i := 0; i < needed; i++ {
		time.Sleep(staggerDelay)

		rawYamuxSession, mimicType, err := np.dialer()
		if err == nil && rawYamuxSession != nil {

			// Initialize with our customized Chaos Wrapper (Token Bucket + protocol-aware
			// retirement budget are rolled inside).
			wrappedSession := NewYamuxSession(rawYamuxSession, np.baseLimitMbps, np.jitterMbps, mimicType, np.lifecycle)

			np.mu.Lock()
			// Admit a fresh ACTIVE pipe when we still need one. Gating on active count
			// is the fix for issue #23. At the total-session cap, evict the oldest
			// draining pipe (they are on their way out) to make room, so the pool can
			// always reach maxConnections active pipes without ever exceeding the cap
			// or starving.
			switch {
			case np.activeCountLocked() >= np.maxConnections:
				wrappedSession.Close() // enough active pipes already
			case len(np.sessions) >= maxTotalFactor*np.maxConnections && !np.evictOldestDrainingLocked():
				wrappedSession.Close() // at the cap with nothing to evict (fail-safe; can't happen while active < max)
			default:
				np.sessions = append(np.sessions, wrappedSession)
				slog.Info("scaled up: dialed new connection", "node", np.Alias, "pool", np.label,
					"active", np.activeCountLocked(), "total", len(np.sessions), "max", np.maxConnections)
			}
			np.mu.Unlock()
		} else {
			slog.Warn("failed to dial new connection", "node", np.Alias, "pool", np.label, "err", err)
		}
	}
}

// GetStats returns aggregated telemetry (TCP + UDP sub-pools) for the dashboard.
func (hm *HubManager) GetStats(nodeAlias string) PoolStats {
	np, err := hm.lookup(nodeAlias)
	if err != nil {
		return PoolStats{}
	}
	tcp := np.tcp.stats()
	udp := np.udp.stats()
	return PoolStats{
		ActiveConns:   tcp.ActiveConns + udp.ActiveConns,
		DrainingConns: tcp.DrainingConns + udp.DrainingConns,
		TotalMbps:     tcp.TotalMbps + udp.TotalMbps,
	}
}

// stats snapshots one pool's connection counts and bandwidth.
func (np *NodePool) stats() PoolStats {
	np.mu.RLock()
	defer np.mu.RUnlock()

	var active, draining int
	for _, s := range np.sessions {
		if s.IsActive() {
			active++
		} else if s.IsDraining() {
			draining++
		}
	}
	return PoolStats{
		ActiveConns:   active,
		DrainingConns: draining,
		TotalMbps:     int(atomic.LoadInt32(&np.currentMbps)),
	}
}

func (np *NodePool) cleanup() {
	np.mu.Lock()
	defer np.mu.Unlock()
	for _, session := range np.sessions {
		session.Close()
	}
	np.sessions = nil
}
