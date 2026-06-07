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
	minConnections  = 5
	defaultMaxConns = 15
	staggerDelay    = 500 * time.Millisecond
	healthCheckFreq = 10 * time.Second
)

// YamuxSession wraps the HashiCorp Yamux multiplexer session along with its metadata.
type YamuxSession struct {
	session      *yamux.Session
	lastActivity time.Time
	mu           sync.RWMutex
}

// OpenStream opens a new logical stream over the existing multiplexed physical connection.
func (ys *YamuxSession) OpenStream() (net.Conn, error) {
	stream, err := ys.session.OpenStream()
	if err == nil {
		ys.mu.Lock()
		ys.lastActivity = time.Now()
		ys.mu.Unlock()
	}
	return stream, err
}

// IsClosed checks if the underlying Yamux session is dead or terminated.
func (ys *YamuxSession) IsClosed() bool {
	return ys.session.IsClosed()
}

// Close gracefully shuts down the multiplexer session and the underlying TCP connection.
func (ys *YamuxSession) Close() error {
	return ys.session.Close()
}

// IdleTime calculates how long the session has been inactive.
func (ys *YamuxSession) IdleTime() time.Duration {
	ys.mu.RLock()
	defer ys.mu.RUnlock()
	return time.Since(ys.lastActivity)
}

// DialFunc is the signature for the function that creates a new authenticated TCP connection,
// performs the SSH handshake, and returns a fully initialized Yamux Client Session.
type DialFunc func() (*yamux.Session, error)

// NodePool manages an auto-scaling pool of Yamux sessions to a single foreign server.
type NodePool struct {
	Alias          string
	TargetIP       string
	maxConnections int
	dialer         DialFunc
	sessions       []*YamuxSession
	mu             sync.RWMutex
	roundRobin     uint64
	shutdown       chan struct{}
}

// HubManager oversees all active foreign node pools in the Iran Hub.
type HubManager struct {
	pools map[string]*NodePool
	mu    sync.RWMutex
}

// NewHubManager initializes the global pool manager for the Iran relay node.
func NewHubManager() *HubManager {
	return &HubManager{
		pools: make(map[string]*NodePool),
	}
}

// RegisterNode provisions a new isolated connection pool for a specific foreign server.
func (hm *HubManager) RegisterNode(cfg config.ForeignNode, dialer DialFunc) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Handle dynamic max connections (fallback to default if not configured)
	maxConns := cfg.MaxConnections
	if maxConns < minConnections {
		maxConns = defaultMaxConns
	}

	pool := &NodePool{
		Alias:          cfg.Alias,
		TargetIP:       cfg.TargetIP,
		maxConnections: maxConns,
		dialer:         dialer,
		sessions:       make([]*YamuxSession, 0, maxConns),
		shutdown:       make(chan struct{}),
	}

	hm.pools[cfg.Alias] = pool
	go pool.monitorAndScale() // Start the dedicated watchdog for this node
}

// GetStream selects a physical connection using Round-Robin and opens a logical stream for the user payload.
func (hm *HubManager) GetStream(nodeAlias string) (net.Conn, error) {
	hm.mu.RLock()
	pool, exists := hm.pools[nodeAlias]
	hm.mu.RUnlock()

	if !exists {
		return nil, errors.New("foreign node pool not found")
	}

	return pool.getStreamRoundRobin()
}

// getStreamRoundRobin distributes user streams evenly across available active Yamux sessions.
func (np *NodePool) getStreamRoundRobin() (net.Conn, error) {
	np.mu.RLock()
	activeCount := len(np.sessions)
	np.mu.RUnlock()

	if activeCount == 0 {
		return nil, errors.New("no active connections available in the pool")
	}

	// Atomic increment for lock-free, thread-safe Round-Robin distribution
	idx := atomic.AddUint64(&np.roundRobin, 1) % uint64(activeCount)

	np.mu.RLock()
	session := np.sessions[idx]
	np.mu.RUnlock()

	if session.IsClosed() {
		return nil, errors.New("selected session is dead, watchdog will clean it up")
	}

	return session.OpenStream()
}

// monitorAndScale is the background watchdog responsible for staggered dialing,
// health checking, and randomized idle teardowns.
func (np *NodePool) monitorAndScale() {
	ticker := time.NewTicker(healthCheckFreq)
	defer ticker.Stop()

	// Initial warmup: Staggered dial to reach minConnections
	np.replenishPool(minConnections)

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

// evaluateHealthAndScale performs cleanup of frozen connections and scales down idle ones.
func (np *NodePool) evaluateHealthAndScale() {
	np.mu.Lock()
	var healthySessions []*YamuxSession

	// Random timeout between 60s and 120s to evade DPI predictability
	dynamicIdleLimit := time.Duration(rand.Intn(61)+60) * time.Second

	for _, session := range np.sessions {
		if session.IsClosed() {
			log.Printf("[Pool-%s] Purged dead/frozen physical connection.\n", np.Alias)
			continue // Discard dead/frozen sessions
		}

		// Scale-Down Logic: Drop excess connections that have been idle too long
		if len(healthySessions) >= minConnections && session.IdleTime() > dynamicIdleLimit {
			session.Close() // Graceful teardown
			log.Printf("[Pool-%s] Scaled DOWN: Dropped idle connection. Active: %d\n", np.Alias, len(healthySessions))
			continue
		}

		healthySessions = append(healthySessions, session)
	}

	np.sessions = healthySessions
	currentCount := len(np.sessions)
	np.mu.Unlock()

	// Scale-Up / Replenish Logic: Ensure minimum baseline is met safely
	if currentCount < minConnections {
		np.replenishPool(minConnections - currentCount)
	}
}

// replenishPool dials new physical connections one-by-one to prevent TCP SYN flood detection.
func (np *NodePool) replenishPool(needed int) {
	for i := 0; i < needed; i++ {
		// Staggered dialing to mimic human/natural network behavior
		time.Sleep(staggerDelay)

		rawYamuxSession, err := np.dialer()
		if err == nil && rawYamuxSession != nil {

			wrappedSession := &YamuxSession{
				session:      rawYamuxSession,
				lastActivity: time.Now(),
			}

			np.mu.Lock()
			if len(np.sessions) < np.maxConnections {
				np.sessions = append(np.sessions, wrappedSession)
				log.Printf("[Pool-%s] Scaled UP: +1 connection established. Active: %d/%d\n", np.Alias, len(np.sessions), np.maxConnections)
			} else {
				// Pool reached its dynamic maximum limit, discard the newly dialed session
				wrappedSession.Close()
			}
			np.mu.Unlock()
		} else {
			log.Printf("[Pool-%s] Failed to dial new connection: %v\n", np.Alias, err)
		}
	}
}

// cleanup gracefully terminates all active sessions during node shutdown.
func (np *NodePool) cleanup() {
	np.mu.Lock()
	defer np.mu.Unlock()
	for _, session := range np.sessions {
		session.Close()
	}
	np.sessions = nil
}