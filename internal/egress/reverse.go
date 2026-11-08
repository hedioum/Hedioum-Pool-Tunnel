package egress

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimicfactory"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tlscert"
)

// Reverse tunnel, foreign side. Instead of waiting for the hub to dial in, the
// foreign dials OUT to the hub's reverse listeners and keeps a target number of
// authenticated pipes open. Over each pipe the foreign is the camouflage CLIENT (it
// dialed) but the yamux SERVER: the hub still opens every logical stream, so the
// stream handling below (TCP, UDP, speedtest, SSRF policy) is exactly the forward
// path's.

const (
	reverseTickEvery   = 3 * time.Second  // how often the pipe count is reconciled
	reverseDialTimeout = 8 * time.Second  // TCP connect timeout per attempt
	reverseMaxAttempts = 4                // candidate endpoints tried per dial
	reverseFailLimit   = 2                // consecutive fails before an endpoint cools down
	reverseCoolBase    = 30 * time.Second // first cooldown for a failing endpoint (doubles)
	reverseCoolMax     = 5 * time.Minute
	reverseBackoffMax  = 60 * time.Second // cap on the pause after a fully failed round
)

// Pipe scaling between a hub's min and max: the foreign opens another pipe when the
// open streams per pipe are high, and closes an idle one after a quiet spell.
const (
	reverseScaleUpStreams = 6                // mean open streams per pipe that triggers one more pipe
	reverseScaleUpGap     = 10 * time.Second // minimum time between two scale-ups
	reverseIdleShrink     = 3 * time.Minute  // idle time before a pipe above min is closed
	reverseEarlyClose     = 3 * time.Second  // a pipe the hub drops sooner than this counts as a failed dial
)

// reverseDialer keeps between min and max authenticated pipes open to one hub.
type reverseDialer struct {
	name    string
	targets []config.Endpoint
	token   string
	min     int
	max     int

	mu        sync.Mutex
	want      int // current target, min <= want <= max
	sessions  []*reversePipe
	health    map[string]*reverseHealth // keyed by endpoint target
	lastUp    time.Time
	idleSince time.Time
}

// reversePipe is one live pipe and where it was dialed.
type reversePipe struct {
	sess    *yamux.Session
	target  string
	started time.Time
}

type reverseHealth struct {
	fails         int
	cooldownUntil time.Time
}

// StartReverseDialOut runs one dial-out loop per hub until the process exits. It is a
// no-op when the config has no reverse hubs.
func StartReverseDialOut(cfg *config.AppConfig) {
	for _, h := range cfg.EffectiveReverseHubs() {
		d := &reverseDialer{
			name:    h.Name,
			targets: h.Targets,
			token:   h.AuthToken,
			min:     h.MinConns,
			max:     h.MaxConns,
			want:    h.MinConns,
			health:  map[string]*reverseHealth{},
		}
		slog.Info("reverse dial-out starting", "hub", d.name, "targets", len(d.targets), "min_pipes", d.min, "max_pipes", d.max)
		go d.run()
	}
}

func (d *reverseDialer) run() {
	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			time.Sleep(backoff)
		}
		live := d.liveCount()
		d.rescale(live)
		if live >= d.currentWant() {
			backoff = 0
			time.Sleep(reverseTickEvery)
			continue
		}
		// Stagger dials (as the hub does in forward mode) so the foreign never opens a
		// burst of identical connections.
		time.Sleep(time.Duration(200+rand.IntN(600)) * time.Millisecond)
		if err := d.dialOne(); err != nil {
			backoff = nextBackoff(backoff)
			slog.Warn("reverse dial failed on every candidate", "hub", d.name, "err", err, "retry_in", backoff)
			continue
		}
		backoff = 0
	}
}

func (d *reverseDialer) currentWant() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.want
}

// rescale moves the target pipe count between min and max from the current load: one
// more pipe when the streams per pipe are high (at most one step per reverseScaleUpGap),
// one fewer after reverseIdleShrink without any open stream. The oldest idle pipe is
// closed on a shrink; the hub simply sees it end.
func (d *reverseDialer) rescale(live int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.max <= d.min {
		d.want = d.min
		return
	}
	streams := 0
	for _, p := range d.sessions {
		streams += p.sess.NumStreams()
	}
	now := time.Now()
	switch {
	case live > 0 && streams >= reverseScaleUpStreams*live && d.want < d.max && now.Sub(d.lastUp) >= reverseScaleUpGap && live >= d.want:
		d.want++
		d.lastUp = now
		d.idleSince = time.Time{}
		slog.Info("reverse pipes scaling up", "hub", d.name, "pipes", d.want, "streams", streams)
	case streams == 0:
		if d.idleSince.IsZero() {
			d.idleSince = now
		}
		if now.Sub(d.idleSince) >= reverseIdleShrink && d.want > d.min {
			d.want--
			d.idleSince = now
			for i, p := range d.sessions { // oldest first
				if p.sess.NumStreams() == 0 {
					_ = p.sess.Close()
					d.sessions = append(d.sessions[:i], d.sessions[i+1:]...)
					break
				}
			}
			slog.Info("reverse pipes scaling down", "hub", d.name, "pipes", d.want)
		}
	default:
		d.idleSince = time.Time{}
	}
}

func nextBackoff(cur time.Duration) time.Duration {
	if cur == 0 {
		return 2 * time.Second
	}
	cur *= 2
	if cur > reverseBackoffMax {
		cur = reverseBackoffMax
	}
	return cur
}

// liveCount prunes closed sessions and returns how many pipes are still up. A pipe
// the hub drops within seconds of the handshake (the hub's pool is full, or it does not
// know this token) counts against its endpoint, so a misconfigured hub cools down
// instead of being redialed in a tight loop.
func (d *reverseDialer) liveCount() int {
	d.mu.Lock()
	var early []string
	kept := d.sessions[:0]
	for _, p := range d.sessions {
		if !p.sess.IsClosed() {
			kept = append(kept, p)
		} else if time.Since(p.started) < reverseEarlyClose {
			early = append(early, p.target)
		}
	}
	d.sessions = kept
	n := len(kept)
	d.mu.Unlock()
	for _, t := range early {
		d.record(t, false)
	}
	return n
}

// order returns the candidate endpoints for one dial: reachable ones in random order
// first (a fresh random mimic per pipe), then cooling-down ones as a last resort,
// capped at reverseMaxAttempts.
func (d *reverseDialer) order() []config.Endpoint {
	now := time.Now()
	d.mu.Lock()
	var ok, cooling []config.Endpoint
	for _, ep := range d.targets {
		if h := d.health[ep.Target]; h != nil && h.cooldownUntil.After(now) {
			cooling = append(cooling, ep)
		} else {
			ok = append(ok, ep)
		}
	}
	d.mu.Unlock()
	rand.Shuffle(len(ok), func(i, j int) { ok[i], ok[j] = ok[j], ok[i] })
	out := append(ok, cooling...)
	if len(out) > reverseMaxAttempts {
		out = out[:reverseMaxAttempts]
	}
	return out
}

func (d *reverseDialer) record(target string, success bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h := d.health[target]
	if h == nil {
		h = &reverseHealth{}
		d.health[target] = h
	}
	if success {
		h.fails, h.cooldownUntil = 0, time.Time{}
		return
	}
	h.fails++
	if h.fails >= reverseFailLimit {
		back := reverseCoolBase << uint(h.fails-reverseFailLimit)
		if back <= 0 || back > reverseCoolMax {
			back = reverseCoolMax
		}
		h.cooldownUntil = time.Now().Add(back)
	}
}

// dialOne establishes one pipe, trying candidate endpoints until one completes the
// mimic handshake, then serves the hub's streams over it.
func (d *reverseDialer) dialOne() error {
	var lastErr error
	for _, ep := range d.order() {
		session, err := dialReverse(ep, d.token)
		if err != nil {
			d.record(ep.Target, false)
			slog.Warn("reverse pipe dial failed", "hub", d.name, "mimic", ep.Mimic, "target", ep.Target, "err", err)
			lastErr = err
			continue
		}
		d.record(ep.Target, true)
		slog.Info("reverse pipe established", "hub", d.name, "mimic", ep.Mimic, "target", ep.Target)

		d.mu.Lock()
		d.sessions = append(d.sessions, &reversePipe{sess: session, target: ep.Target, started: time.Now()})
		d.mu.Unlock()
		go handleYamuxSession(session)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reverse targets configured")
	}
	return lastErr
}

// dialReverse connects to one hub listener and returns the yamux SERVER session over
// the authenticated mimic connection.
func dialReverse(ep config.Endpoint, token string) (*yamux.Session, error) {
	conn, err := net.DialTimeout("tcp", ep.Target, reverseDialTimeout)
	if err != nil {
		return nil, err
	}
	secureConn, err := mimicfactory.Client(ep, token).Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s mimic handshake failed: %w", ep.Mimic, err)
	}
	session, err := yamux.Server(secureConn, foreignYamuxConfig())
	if err != nil {
		secureConn.Close()
		return nil, err
	}
	return session, nil
}

// foreignYamuxConfig is the yamux configuration the egress uses for hub sessions
// (the hub runs its own randomized keep-alives, so ours stay off).
func foreignYamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = false
	c.MaxStreamWindowSize = 4 * 1024 * 1024
	c.StreamCloseTimeout = 3 * time.Minute
	return c
}

// BuildServerMimic exposes the egress's server-side camouflage builder so the Iran
// hub's reverse listeners wear exactly the same mimics (same decoys, same auth).
func BuildServerMimic(token, decoyStyle string, ml config.MimicListener, filter *securestream.ReplayFilter, certMgr *tlscert.CertManager) (mimic.ServerMimic, error) {
	return buildServerMimic(&config.AppConfig{AuthToken: token, DecoyStyle: decoyStyle}, ml, filter, certMgr)
}

// BuildSharedServerMimic is BuildServerMimic for a listener shared by several reverse
// nodes: it accepts any of tokens (the first one also seeds the decoy identity) and
// the matching index is read back with mimic.MatchedToken. SSH cannot be shared.
func BuildSharedServerMimic(tokens []string, decoyStyle string, ml config.MimicListener, filter *securestream.ReplayFilter, certMgr *tlscert.CertManager) (mimic.ServerMimic, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens for the shared listener")
	}
	m, err := BuildServerMimic(tokens[0], decoyStyle, ml, filter, certMgr)
	if err != nil {
		return nil, err
	}
	if len(tokens) > 1 && !mimic.SetExtraTokens(m, tokens[1:]) {
		return nil, fmt.Errorf("the %s mimic cannot share a listener between nodes", ml.Type)
	}
	return m, nil
}
