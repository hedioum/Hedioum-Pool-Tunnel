package pool

import (
	"errors"
	"log"
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
)

// DialFunc is the signature for the function that creates a new authenticated TCP connection.
type DialFunc func() (*yamux.Session, error)

// PoolStats holds real-time telemetry data for the interactive dashboard.
type PoolStats struct {
	ActiveConns   int
	DrainingConns int
	TotalMbps     int
}

// NodePool manages an auto-scaling pool of Yamux sessions to a single foreign server.
type NodePool struct {
	Alias          string
	TargetIP       string
	minConnections int
	maxConnections int
	baseLimitMbps  int
	jitterMbps     int
	dialer         DialFunc
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
func newNodePool(cfg config.ForeignNode, minConns, maxConns int, dialer DialFunc) *NodePool {
	pool := &NodePool{
		Alias:          cfg.Alias,
		TargetIP:       cfg.TargetIP,
		minConnections: minConns,
		maxConnections: maxConns,
		baseLimitMbps:  cfg.BandwidthLimitMbps,
		jitterMbps:     cfg.BandwidthJitterMbps,
		dialer:         dialer,
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

	hm.pools[cfg.Alias] = &nodePools{
		tcp: newNodePool(cfg, minConns, maxConns, dialer),
		udp: newNodePool(cfg, udpMinConns, udpMaxConns, dialer),
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
			log.Printf("[Pool-%s] Purged dead/frozen physical connection.\n", np.Alias)
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

			// Scale-Up trigger: If this connection is pushing beyond 80% of its Chaos Cap
			if mbps >= int(float64(cap)*0.8) {
				needsScaleUp = true
			}

			// Scale-Down logic: Drop excess connections that are barely moving traffic
			if activeCount > np.minConnections && mbps < 1 && s.IdleTime() > dynamicIdleLimit {
				s.SetDraining() // Shift to Draining (Wait for logical streams to drop to zero)
				activeCount--
				log.Printf("[Pool-%s] Scaled DOWN: Connection moved to Draining state (Idle/Low load).\n", np.Alias)
			}
		} else if s.IsDraining() {
			// Deep cleanup: Only close a draining session when ALL its streams have naturally finished
			if s.ActiveStreams() == 0 {
				s.Close()
				log.Printf("[Pool-%s] Draining complete. Empty connection closed safely.\n", np.Alias)
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

	// 3. Guarantee baseline availability safely based on MinConnections
	np.mu.RLock()
	currentActive := 0
	for _, s := range np.sessions {
		if s.IsActive() {
			currentActive++
		}
	}
	np.mu.RUnlock()

	if currentActive < np.minConnections {
		np.replenishPool(np.minConnections - currentActive)
	}
}

// executeScaleUp prioritizes reviving a draining connection; if none exist, dials a new one.
func (np *NodePool) executeScaleUp() {
	np.mu.Lock()

	// Fast Path: Revive a draining connection (Zero Overhead)
	for _, s := range np.sessions {
		if s.IsDraining() {
			s.Revive()
			log.Printf("[Pool-%s] Scaled UP (Revive): Resurrected a draining connection back to Active.\n", np.Alias)
			np.mu.Unlock()
			return
		}
	}

	totalConns := len(np.sessions)
	np.mu.Unlock()

	// Slow Path: Dial a new physical connection
	if totalConns < np.maxConnections {
		np.replenishPool(1)
	} else {
		log.Printf("[Pool-%s] Warning: Max physical limits reached (%d). Cannot scale further.\n", np.Alias, np.maxConnections)
	}
}

func (np *NodePool) replenishPool(needed int) {
	for i := 0; i < needed; i++ {
		time.Sleep(staggerDelay)

		rawYamuxSession, err := np.dialer()
		if err == nil && rawYamuxSession != nil {

			// Initialize with our customized Chaos Wrapper (Token Bucket is initialized inside)
			wrappedSession := NewYamuxSession(rawYamuxSession, np.baseLimitMbps, np.jitterMbps)

			np.mu.Lock()
			if len(np.sessions) < np.maxConnections {
				np.sessions = append(np.sessions, wrappedSession)
				log.Printf("[Pool-%s] Scaled UP (Dial): +1 connection established. Total Pipes: %d/%d\n", np.Alias, len(np.sessions), np.maxConnections)
			} else {
				wrappedSession.Close()
			}
			np.mu.Unlock()
		} else {
			log.Printf("[Pool-%s] Failed to dial new connection: %v\n", np.Alias, err)
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
