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
