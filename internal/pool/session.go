package pool

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"
)

const (
	StateActive   int32 = 0
	StateDraining int32 = 1 // Connection is waiting for active logical streams to finish
)

// YamuxSession wraps the HashiCorp Yamux multiplexer with our Chaos Balancing metadata.
type YamuxSession struct {
	session *yamux.Session
	state   int32 // Atomic state: Active vs Draining

	// Atomic counters for real-time bandwidth calculation (Bytes)
	bytesTransferred uint64

	// Chaos Mesh / DPI Evasion Parameters
	baseLimitMbps  int
	jitterMbps     int
	currentCapMbps int

	// Token Bucket Rate Limiter (Hard Limit)
	limiter *rate.Limiter

	lastActivity time.Time
	mu           sync.RWMutex
}

// NewYamuxSession initializes a monitored physical connection with a randomized bandwidth cap.
func NewYamuxSession(ys *yamux.Session, baseLimit, jitter int) *YamuxSession {
	s := &YamuxSession{
		session:       ys,
		state:         StateActive,
		baseLimitMbps: baseLimit,
		jitterMbps:    jitter,
		lastActivity:  time.Now(),
	}
	s.UpdateChaosLimit() // Initialize the first fluctuating cap and token bucket
	return s
}

// monitoredStream is a Decorator for net.Conn that intercepts IO operations to count bytes and shape traffic.
type monitoredStream struct {
	net.Conn
	parent *YamuxSession
	ctx    context.Context    // canceled when this stream closes
	cancel context.CancelFunc // releases any in-flight rate-limit Wait
}

// Close cancels the stream context so a goroutine blocked in the rate limiter's
// WaitN returns promptly instead of waiting out the full token delay.
func (m *monitoredStream) Close() error {
	m.cancel()
	return m.Conn.Close()
}

func (m *monitoredStream) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&m.parent.bytesTransferred, uint64(n))

		// Enforce Hard Rate Limit (Token Bucket) AFTER reading.
		// This forces the app to consume data slowly, filling up the OS socket buffer.
		// The OS will then naturally reduce the TCP Window Size (Backpressure), slowing down the sender.
		toWait := n
		burst := m.parent.limiter.Burst()
		if toWait > burst {
			toWait = burst // Clamp to burst size to prevent WaitN from returning an error
		}
		// Bound the wait to the stream's lifetime; on close WaitN returns immediately.
		_ = m.parent.limiter.WaitN(m.ctx, toWait)
	}
	return n, err
}

func (m *monitoredStream) Write(b []byte) (int, error) {
	// Enforce Hard Rate Limit BEFORE writing.
	// This prevents dumping huge payloads into the OS buffer instantly, smoothing out outbound traffic.
	if len(b) > 0 {
		toWait := len(b)
		burst := m.parent.limiter.Burst()
		if toWait > burst {
			toWait = burst
		}
		_ = m.parent.limiter.WaitN(m.ctx, toWait)
	}

	n, err := m.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&m.parent.bytesTransferred, uint64(n))
	}
	return n, err
}

// OpenStream opens a new logical stream, wrapping it in our bandwidth monitor & shaper.
func (ys *YamuxSession) OpenStream() (net.Conn, error) {
	stream, err := ys.session.OpenStream()
	if err == nil {
		ys.mu.Lock()
		ys.lastActivity = time.Now()
		ys.mu.Unlock()
		// Wrap the native stream to intercept, count, and throttle traffic
		ctx, cancel := context.WithCancel(context.Background())
		return &monitoredStream{Conn: stream, parent: ys, ctx: ctx, cancel: cancel}, nil
	}
	return nil, err
}

// GetAndResetBytes atomically fetches the total transferred bytes since the last check, and resets the counter to 0.
func (ys *YamuxSession) GetAndResetBytes() uint64 {
	return atomic.SwapUint64(&ys.bytesTransferred, 0)
}

// UpdateChaosLimit shifts the bandwidth cap randomly and updates the Hard Rate Limiter.
func (ys *YamuxSession) UpdateChaosLimit() {
	ys.mu.Lock()
	defer ys.mu.Unlock()

	if ys.jitterMbps == 0 {
		ys.currentCapMbps = ys.baseLimitMbps
	} else {
		// Calculate a random variance between -jitter and +jitter
		variance := rand.Intn((ys.jitterMbps*2)+1) - ys.jitterMbps
		ys.currentCapMbps = ys.baseLimitMbps + variance
	}

	// Ensure the cap never drops to zero or below
	if ys.currentCapMbps < 1 {
		ys.currentCapMbps = 1
	}

	// Convert Mbps to Bytes per Second (Bps)
	bytesPerSec := float64(ys.currentCapMbps) * 1024 * 1024 / 8

	// Update or Initialize the Token Bucket Limiter
	// Burst size is set to 2MB to allow normal TCP window scaling, while strictly enforcing the sustained Bps rate.
	if ys.limiter == nil {
		ys.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), 2*1024*1024)
	} else {
		ys.limiter.SetLimit(rate.Limit(bytesPerSec))
	}
}

// CurrentCap returns the active fluctuating limit for this specific connection.
func (ys *YamuxSession) CurrentCap() int {
	ys.mu.RLock()
	defer ys.mu.RUnlock()
	return ys.currentCapMbps
}

// --- State Management (Active / Draining) ---

func (ys *YamuxSession) SetDraining() {
	atomic.StoreInt32(&ys.state, StateDraining)
}

func (ys *YamuxSession) Revive() {
	atomic.StoreInt32(&ys.state, StateActive)
}

func (ys *YamuxSession) IsDraining() bool {
	return atomic.LoadInt32(&ys.state) == StateDraining
}

func (ys *YamuxSession) IsActive() bool {
	return atomic.LoadInt32(&ys.state) == StateActive
}

// --- Core Wrapper Functions ---

func (ys *YamuxSession) ActiveStreams() int {
	if ys.session == nil || ys.session.IsClosed() {
		return 0
	}
	return ys.session.NumStreams()
}

func (ys *YamuxSession) IsClosed() bool {
	return ys.session.IsClosed()
}

func (ys *YamuxSession) Close() error {
	return ys.session.Close()
}

func (ys *YamuxSession) IdleTime() time.Duration {
	ys.mu.RLock()
	defer ys.mu.RUnlock()
	return time.Since(ys.lastActivity)
}
