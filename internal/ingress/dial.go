package ingress

import (
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimicfactory"
)

// hubYamuxConfig tunes Yamux for high-latency, high-throughput WAN links.
func hubYamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = false        // we run a custom randomized heartbeat
	c.MaxStreamWindowSize = 16 << 20 // 16MB: headroom for 200-300 Mbps at high RTT
	c.StreamCloseTimeout = 3 * time.Minute
	return c
}

// clientMimicFor builds the client camouflage for an endpoint's mimic type.
func clientMimicFor(ep config.Endpoint, token string) mimic.ClientMimic {
	return mimicfactory.Client(ep, token)
}

// DialEndpoint dials one endpoint: TCP connect, mimic handshake, Yamux client.
// Shared by the pool dialer and the speedtest CLI.
func DialEndpoint(ep config.Endpoint, token string, cfg *yamux.Config) (*yamux.Session, error) {
	conn, err := net.DialTimeout("tcp", ep.Target, 8*time.Second)
	if err != nil {
		return nil, err
	}
	secureConn, err := clientMimicFor(ep, token).Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s mimic handshake failed: %w", ep.Mimic, err)
	}
	session, err := yamux.Client(secureConn, cfg)
	if err != nil {
		secureConn.Close()
		return nil, err
	}
	return session, nil
}

// ProbeEndpoint dials one endpoint end-to-end (TCP + mimic handshake + yamux) and
// pings it through the tunnel to confirm the egress is actually alive, returning
// the round-trip latency. It tears the probe connection down before returning. The
// `probe` command uses it to report which mimics on a node are reachable and which
// are blocked (wrong port, censored protocol, dead egress).
func ProbeEndpoint(ep config.Endpoint, token string) (time.Duration, error) {
	sess, err := DialEndpoint(ep, token, hubYamuxConfig())
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	return sess.Ping() // real round-trip through the mux -> proves the pipe works
}

// endpointDialer spreads new physical pipes across a node's endpoints with random
// per-node weights (Chaos Mesh v2 — no fixed "10 SSH + 0 others" signature), and
// tracks per-endpoint reachability so a censored entry port (e.g. an ISP that drops
// outbound :22) is detected, skipped, and periodically retried. Each dial races across
// candidate ports, so the tunnel still comes up when some ports are blocked.
type endpointDialer struct {
	node    config.ForeignNode
	cfg     *yamux.Config
	weights []float64

	mu     sync.Mutex
	health map[string]*epHealth // keyed by endpoint.Target
}

type epHealth struct {
	fails         int
	cooldownUntil time.Time
}

const (
	dialMaxAttempts = 4                // candidate ports tried per dial (bounds a down-node stall)
	epFailThreshold = 2                // consecutive fails before an endpoint is cooled down
	epCooldownBase  = 60 * time.Second // first cooldown for a blocked endpoint (doubles per extra fail)
	epCooldownMax   = 10 * time.Minute
)

// dialPriority orders fallback attempts by how likely a port is to be reachable from
// a censored network: 443/8443 first, ssh last (it is the most commonly blocked).
var dialPriority = map[string]int{
	"tls": 0, "https-alt": 1,
	"smtps": 2, "imaps": 2, "directadmin": 2, "cpanel": 2, "whm": 2, "webmail": 2,
	"grafana": 2, "prometheus": 2, "docker": 2,
	"smtp": 3, "imap": 3, "postgres": 4, "mysql": 4, "ssh": 5,
}

func dialRank(m string) int {
	if r, ok := dialPriority[m]; ok {
		return r
	}
	return 3
}

func newEndpointDialer(node config.ForeignNode) *endpointDialer {
	w := make([]float64, len(node.Endpoints))
	for i := range w {
		w[i] = 0.3 + mrand.Float64() // per-node random bias
	}
	return &endpointDialer{node: node, cfg: hubYamuxConfig(), weights: w, health: map[string]*epHealth{}}
}

// attemptOrder returns the endpoints to try for one dial, best-first: a weighted-
// random primary pick among currently-reachable endpoints (for mimic diversity), then
// the remaining reachable endpoints in innocuous-port-first order, then any
// cooling-down endpoints as a last resort. Capped at dialMaxAttempts.
func (d *endpointDialer) attemptOrder() []config.Endpoint {
	eps := d.node.Endpoints
	if len(eps) <= 1 {
		return eps
	}
	now := time.Now()
	d.mu.Lock()
	var reachable, cooling []int
	for i, ep := range eps {
		if h := d.health[ep.Target]; h != nil && h.cooldownUntil.After(now) {
			cooling = append(cooling, i)
		} else {
			reachable = append(reachable, i)
		}
	}
	d.mu.Unlock()

	pool := reachable
	if len(pool) == 0 { // everything cooled down — try anyway, the block may have lifted
		pool, cooling = cooling, nil
	}

	primary := d.weightedPick(pool)
	seen := map[int]bool{primary: true}
	order := []int{primary}

	rest := append([]int(nil), pool...)
	sort.SliceStable(rest, func(a, b int) bool {
		return dialRank(eps[rest[a]].Mimic) < dialRank(eps[rest[b]].Mimic)
	})
	for _, i := range rest {
		if !seen[i] {
			order = append(order, i)
			seen[i] = true
		}
	}
	order = append(order, cooling...)
	if len(order) > dialMaxAttempts {
		order = order[:dialMaxAttempts]
	}
	out := make([]config.Endpoint, len(order))
	for i, idx := range order {
		out[i] = eps[idx]
	}
	return out
}

// weightedPick returns a weighted-random index from the candidate indices.
func (d *endpointDialer) weightedPick(cand []int) int {
	if len(cand) == 1 {
		return cand[0]
	}
	total := 0.0
	for _, i := range cand {
		total += d.weights[i]
	}
	r := mrand.Float64() * total
	for _, i := range cand {
		if r -= d.weights[i]; r <= 0 {
			return i
		}
	}
	return cand[len(cand)-1]
}

func (d *endpointDialer) recordSuccess(target string) {
	d.mu.Lock()
	if h := d.health[target]; h != nil {
		h.fails, h.cooldownUntil = 0, time.Time{}
	}
	d.mu.Unlock()
}

func (d *endpointDialer) recordFailure(target string) {
	d.mu.Lock()
	h := d.health[target]
	if h == nil {
		h = &epHealth{}
		d.health[target] = h
	}
	h.fails++
	if h.fails >= epFailThreshold {
		back := epCooldownBase << uint(h.fails-epFailThreshold)
		if back <= 0 || back > epCooldownMax {
			back = epCooldownMax
		}
		h.cooldownUntil = time.Now().Add(back)
	}
	d.mu.Unlock()
}

// dial establishes one physical pipe, racing across candidate ports so a censored
// entry port does not stop the tunnel from coming up. The first port that completes
// the mimic handshake wins; failures cool the port down so it is skipped next time.
func (d *endpointDialer) dial() (*yamux.Session, string, error) {
	var lastErr error
	for _, ep := range d.attemptOrder() {
		session, err := DialEndpoint(ep, d.node.AuthToken, d.cfg)
		if err != nil {
			d.recordFailure(ep.Target)
			slog.Warn("pipe dial failed", "node", d.node.Alias, "mimic", ep.Mimic, "target", ep.Target, "err", err)
			lastErr = err
			continue
		}
		d.recordSuccess(ep.Target)
		slog.Info("pipe established", "node", d.node.Alias, "mimic", ep.Mimic, "target", ep.Target)
		go keepAlive(session)
		return session, ep.Mimic, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("node %q has no endpoints to dial", d.node.Alias)
	}
	return nil, "", lastErr
}

// keepAlive sends a randomized-interval Yamux ping to evade DPI periodicity checks.
func keepAlive(s *yamux.Session) {
	for {
		if s.IsClosed() {
			return
		}
		time.Sleep(time.Duration(mrand.IntN(26)+20) * time.Second)
		if _, err := s.Ping(); err != nil {
			return
		}
	}
}
