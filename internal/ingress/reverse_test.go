package ingress

import (
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pool"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

const reverseTestToken = "0123456789abcdef0123456789abcdef"

// freePort returns a currently free TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startReverseHub brings up a hub with one reverse node listening on a TLS mimic and
// returns its manager and the listener port.
func startReverseHub(t *testing.T, alias string) (*pool.HubManager, int) {
	t.Helper()
	old := reverseCertDir
	reverseCertDir = t.TempDir()
	t.Cleanup(func() { reverseCertDir = old })

	port := freePort(t)
	node := config.ForeignNode{
		Alias:               alias,
		AuthToken:           reverseTestToken,
		Reverse:             true,
		ReverseListeners:    []config.MimicListener{{Type: "tls", Port: port}},
		MinConnections:      1,
		MaxConnections:      3,
		BandwidthLimitMbps:  100,
		BandwidthJitterMbps: 5,
	}
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{node}}

	hm := pool.NewHubManager()
	hm.RegisterReverseNode(node)
	startReverseListeners(cfg, hm)

	// Wait for the listener to be up.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reverse listener did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hm, port
}

func startReverseForeign(port int, token string, conns int) {
	egress.StartReverseDialOut(&config.AppConfig{
		Role:      "foreign",
		AuthToken: token,
		ReverseTargets: []config.Endpoint{
			{Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Mimic: "tls"},
		},
		ReverseConns: conns,
		ReverseOnly:  true,
	})
}

func waitActive(t *testing.T, hm *pool.HubManager, alias string, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if hm.GetStats(alias).ActiveConns >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d active reverse pipes, got %+v", want, hm.GetStats(alias))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestReverseTunnelEndToEnd: the foreign dials the hub, the hub adopts the pipes into
// its pools (first the UDP sub-pool, then TCP), and the HUB opens streams the foreign
// serves — proving the direction flipped while stream handling is unchanged.
func TestReverseTunnelEndToEnd(t *testing.T) {
	hm, port := startReverseHub(t, "rev1")
	startReverseForeign(port, reverseTestToken, 3)

	// 3 pipes = udpMinConns (2, UDP sub-pool) + 1 TCP.
	waitActive(t, hm, "rev1", 3)

	// A hub-opened TCP stream is served by the foreign: a speedtest download streams
	// real bytes back over the reverse pipe.
	stream, err := hm.GetStreamTCP("rev1")
	if err != nil {
		t.Fatalf("no TCP stream over the reverse pipe: %v", err)
	}
	defer stream.Close()
	if err := tunproto.WriteSpeedtestHeader(stream, tunproto.SpeedDown, 1); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64*1024)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("foreign did not serve the hub's stream: %v", err)
	}

	// The dedicated UDP sub-pool was fed too.
	us, err := hm.GetStreamUDP("rev1")
	if err != nil {
		t.Fatalf("no UDP sub-pool stream: %v", err)
	}
	us.Close()
}

// TestReverseWrongTokenIsRejected: a foreign with a different token never gets a pipe
// adopted — the hub treats it as an unauthorized probe.
func TestReverseWrongTokenIsRejected(t *testing.T) {
	hm, port := startReverseHub(t, "rev2")
	startReverseForeign(port, "ffffffffffffffffffffffffffffffff", 2)

	time.Sleep(4 * time.Second)
	if st := hm.GetStats("rev2"); st.ActiveConns != 0 {
		t.Fatalf("a foreign with the wrong token must not be adopted: %+v", st)
	}
}

// The hub's reverse listener presents a certificate issued for the node's SNI (so the
// name a passive observer sees matches the SNI the foreign sends), and a node's decoy
// style overrides the hub's.
func TestReverseListenerCertMatchesSNIAndDecoyStyle(t *testing.T) {
	old := reverseCertDir
	reverseCertDir = t.TempDir()
	t.Cleanup(func() { reverseCertDir = old })

	port := freePort(t)
	node := config.ForeignNode{
		Alias: "snirev", AuthToken: reverseTestToken, Reverse: true,
		ReverseListeners:  []config.MimicListener{{Type: "tls", Port: port, ServerName: "files.example.test"}},
		ReverseDecoyStyle: "directadmin",
		MinConnections:    1, MaxConnections: 3, BandwidthLimitMbps: 100, BandwidthJitterMbps: 5,
	}
	cfg := &config.AppConfig{Role: "iran", DecoyStyle: "apache", ForeignNodes: []config.ForeignNode{node}}
	hm := pool.NewHubManager()
	hm.RegisterReverseNode(node)
	startReverseListeners(cfg, hm)

	var cn string
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			&tls.Config{ServerName: "files.example.test", InsecureSkipVerify: true})
		if err == nil {
			cn = c.ConnectionState().PeerCertificates[0].Subject.CommonName
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TLS handshake with the reverse listener: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cn != "files.example.test" {
		t.Fatalf("certificate CN = %q, want the node's SNI", cn)
	}
	if got := reverseDecoyStyle(cfg, node); got != "directadmin" {
		t.Fatalf("node decoy must win over the hub's, got %q", got)
	}
	node.ReverseDecoyStyle = ""
	if got := reverseDecoyStyle(cfg, node); got != "apache" {
		t.Fatalf("fallback must be the hub's decoy, got %q", got)
	}
}

// proxyRelay accepts connections, dials the hub, prepends a PROXY v1 header like a front
// proxy with `proxy_protocol on`, and pipes both ways. Returns the relay's port.
func proxyRelay(t *testing.T, hubPort int, withHeader bool) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				u, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hubPort)))
				if err != nil {
					c.Close()
					return
				}
				if withHeader {
					io.WriteString(u, "PROXY TCP4 203.0.113.9 198.51.100.1 40000 443\r\n")
				}
				go func() { io.Copy(u, c); u.Close() }()
				io.Copy(c, u)
				c.Close()
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func startProxiedHub(t *testing.T, alias string, proxyProtocol bool) (*pool.HubManager, int) {
	t.Helper()
	old := reverseCertDir
	reverseCertDir = t.TempDir()
	t.Cleanup(func() { reverseCertDir = old })
	port := freePort(t)
	node := config.ForeignNode{
		Alias: alias, AuthToken: reverseTestToken, Reverse: true,
		ReverseBind: "127.0.0.1", ReverseProxyProtocol: proxyProtocol,
		ReverseListeners: []config.MimicListener{{Type: "tls", Port: port}},
		MinConnections:   1, MaxConnections: 3, BandwidthLimitMbps: 100, BandwidthJitterMbps: 5,
	}
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{node}}
	hm := pool.NewHubManager()
	hm.RegisterReverseNode(node)
	startReverseListeners(cfg, hm)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hm, port
}

// Behind a front proxy: the foreign dials the proxy's port, the proxy prepends the PROXY
// header and forwards to the loopback-bound listener, and the pipes are adopted.
func TestReverseBehindFrontProxy(t *testing.T) {
	hm, hubPort := startProxiedHub(t, "proxied", true)
	startReverseForeign(proxyRelay(t, hubPort, true), reverseTestToken, 3)
	waitActive(t, hm, "proxied", 3)
}

// A listener that requires the PROXY protocol drops anything that skipped the proxy.
func TestReverseProxyProtocolDropsDirectConnections(t *testing.T) {
	hm, hubPort := startProxiedHub(t, "strict", true)
	startReverseForeign(hubPort, reverseTestToken, 2) // straight to the listener, no header
	time.Sleep(4 * time.Second)
	if st := hm.GetStats("strict"); st.ActiveConns != 0 {
		t.Fatalf("connections without a PROXY header must be dropped: %+v", st)
	}
}

// Without PROXY protocol configured, a proxy that sends none works as before.
func TestReverseBehindPlainTCPProxy(t *testing.T) {
	hm, hubPort := startProxiedHub(t, "plain", false)
	startReverseForeign(proxyRelay(t, hubPort, false), reverseTestToken, 3)
	waitActive(t, hm, "plain", 3)
}

const reverseTestToken2 = "fedcba9876543210fedcba9876543210"

// startSharedHub brings up a hub with two reverse nodes on ONE listener (same port,
// type and SNI) with shared_reverse_auth on (or off, to prove the default is strict).
func startSharedHub(t *testing.T, shared bool) (*pool.HubManager, int) {
	t.Helper()
	old := reverseCertDir
	reverseCertDir = t.TempDir()
	t.Cleanup(func() { reverseCertDir = old })

	port := freePort(t)
	mk := func(alias, token string) config.ForeignNode {
		return config.ForeignNode{
			Alias: alias, AuthToken: token, Reverse: true,
			ReverseListeners: []config.MimicListener{{Type: "tls", Port: port, ServerName: "shared.example.com"}},
			MinConnections:   1, MaxConnections: 4,
			BandwidthLimitMbps: 100,
		}
	}
	a, b := mk("sa", reverseTestToken), mk("sb", reverseTestToken2)
	cfg := &config.AppConfig{Role: "iran", SharedReverseAuth: shared, ForeignNodes: []config.ForeignNode{a, b}}
	hm := pool.NewHubManager()
	hm.RegisterReverseNode(a)
	hm.RegisterReverseNode(b)
	startReverseListeners(cfg, hm)

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("shared reverse listener did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hm, port
}

// TestSharedReverseListenerRoutesByToken: two foreigns dial the same port; each one's
// pipes land in the pool of the node whose token it presented.
func TestSharedReverseListenerRoutesByToken(t *testing.T) {
	hm, port := startSharedHub(t, true)
	// The first two pipes of a node feed its UDP sub-pool, so 3 and 4 leave a TCP pipe.
	startReverseForeign(port, reverseTestToken, 3)
	startReverseForeign(port, reverseTestToken2, 4)

	waitActive(t, hm, "sa", 3)
	waitActive(t, hm, "sb", 4)
	time.Sleep(time.Second)
	if a, b := hm.GetStats("sa").ActiveConns, hm.GetStats("sb").ActiveConns; a != 3 || b != 4 {
		t.Fatalf("pipes went to the wrong node: sa=%d (want 3) sb=%d (want 4)", a, b)
	}

	// Each node serves its own foreign.
	for _, alias := range []string{"sa", "sb"} {
		st, err := hm.GetStreamTCP(alias)
		if err != nil {
			t.Fatalf("%s: no stream: %v", alias, err)
		}
		if err := tunproto.WriteSpeedtestHeader(st, tunproto.SpeedDown, 1); err != nil {
			t.Fatal(err)
		}
		_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(st, make([]byte, 32*1024)); err != nil {
			t.Fatalf("%s: foreign did not serve the stream: %v", alias, err)
		}
		st.Close()
	}
}

// TestSharedReverseListenerStillRejectsStrangers: an unknown token is not adopted by
// any node of the shared listener.
func TestSharedReverseListenerStillRejectsStrangers(t *testing.T) {
	hm, port := startSharedHub(t, true)
	startReverseForeign(port, "00000000000000000000000000000000", 2)
	time.Sleep(4 * time.Second)
	if a, b := hm.GetStats("sa").ActiveConns, hm.GetStats("sb").ActiveConns; a != 0 || b != 0 {
		t.Fatalf("stranger adopted: sa=%d sb=%d", a, b)
	}
}

// TestSharedReverseOffKeepsPortsExclusive: with the option off, two nodes on one port
// are a configuration error, and the first node keeps the port.
func TestSharedReverseOffKeepsPortsExclusive(t *testing.T) {
	cfg := &config.AppConfig{ForeignNodes: []config.ForeignNode{
		{Alias: "x", AuthToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Reverse: true, ReverseListeners: []config.MimicListener{{Type: "tls", Port: 8443}}},
		{Alias: "y", AuthToken: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Reverse: true, ReverseListeners: []config.MimicListener{{Type: "tls", Port: 8443}}},
	}}
	groups, problems := reverseGroups(cfg)
	if len(groups) != 1 || len(groups[0].Nodes) != 1 || groups[0].Nodes[0].Alias != "x" || len(problems) != 1 {
		t.Fatalf("groups=%+v problems=%v", groups, problems)
	}
	cfg.SharedReverseAuth = true
	groups, problems = reverseGroups(cfg)
	if len(groups) != 1 || len(groups[0].Nodes) != 2 || len(problems) != 0 {
		t.Fatalf("shared: groups=%+v problems=%v", groups, problems)
	}
	// A different SNI on the same port is not shareable.
	cfg.ForeignNodes[1].ReverseListeners[0].ServerName = "other.example.com"
	if _, problems = reverseGroups(cfg); len(problems) != 1 {
		t.Fatalf("different SNI must not share: %v", problems)
	}
}

// TestOneForeignDialsTwoHubs: a single foreign with two hubs keeps each hub's own
// minimum of pipes open, and both hubs can open streams over theirs.
func TestOneForeignDialsTwoHubs(t *testing.T) {
	hm1, port1 := startReverseHub(t, "hubA")
	hm2, port2 := startReverseHub(t, "hubB")
	ep := func(port int) []config.Endpoint {
		return []config.Endpoint{{Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Mimic: "tls"}}
	}
	egress.StartReverseDialOut(&config.AppConfig{
		Role:        "foreign",
		AuthToken:   reverseTestToken,
		ReverseOnly: true,
		ReverseHubs: []config.ReverseHub{
			{Name: "a", Targets: ep(port1), MinConns: 3, MaxConns: 3},
			{Name: "b", Targets: ep(port2), MinConns: 4, MaxConns: 4},
		},
	})
	waitActive(t, hm1, "hubA", 3)
	waitActive(t, hm2, "hubB", 4)
	time.Sleep(time.Second)
	if a, b := hm1.GetStats("hubA").ActiveConns, hm2.GetStats("hubB").ActiveConns; a != 3 || b != 4 {
		t.Fatalf("each hub must get exactly its own minimum: a=%d (want 3) b=%d (want 4)", a, b)
	}
	for name, hm := range map[string]*pool.HubManager{"hubA": hm1, "hubB": hm2} {
		st, err := hm.GetStreamTCP(name)
		if err != nil {
			t.Fatalf("%s: no stream: %v", name, err)
		}
		if err := tunproto.WriteSpeedtestHeader(st, tunproto.SpeedDown, 1); err != nil {
			t.Fatal(err)
		}
		_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(st, make([]byte, 32*1024)); err != nil {
			t.Fatalf("%s: foreign did not serve the stream: %v", name, err)
		}
		st.Close()
	}
}
