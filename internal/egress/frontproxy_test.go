package egress

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tlscert"
)

const frontProxyToken = "0123456789abcdef0123456789abcdef"

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startTLSListener runs one TLS mimic listener with the given front-proxy settings.
func startTLSListener(t *testing.T, bind string, proxyProtocol bool) int {
	t.Helper()
	port := freeLoopbackPort(t)
	cfg := &config.AppConfig{Role: "foreign", AuthToken: frontProxyToken, DecoyStyle: "apache", ListenBind: bind, ProxyProtocol: proxyProtocol}
	certMgr, err := tlscert.NewCertManager(t.TempDir(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	go startMimicListener(cfg, config.MimicListener{Type: "tls", Port: port}, securestream.NewReplayFilter(0), certMgr)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return port
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// handshake dials addr, optionally sends a PROXY v1 header first (as a front proxy
// does), and runs the client side of the TLS mimic with the right token.
func handshake(addr string, header bool) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if header {
		if _, err := io.WriteString(c, "PROXY TCP4 203.0.113.9 198.51.100.1 40000 443\r\n"); err != nil {
			return err
		}
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	authed, err := (&mimic.TLSClient{Token: frontProxyToken}).Dial(c)
	if err != nil {
		return err
	}
	return authed.Close()
}

// Behind a front proxy: a connection that carries the PROXY header is served, one that
// skipped the proxy is dropped.
func TestForeignListenerRequiresProxyHeader(t *testing.T) {
	port := startTLSListener(t, "127.0.0.1", true)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := handshake(addr, true); err != nil {
		t.Fatalf("a connection through the proxy must authenticate: %v", err)
	}
	if err := handshake(addr, false); err == nil {
		t.Fatal("a connection without a PROXY header must be dropped")
	}
}

// Without the setting, nothing changes: no header expected.
func TestForeignListenerPlainByDefault(t *testing.T) {
	port := startTLSListener(t, "", false)
	if err := handshake(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), false); err != nil {
		t.Fatalf("default listener must keep working: %v", err)
	}
}

// ListenBind really restricts the listener to that address.
func TestForeignListenerBindsToConfiguredAddress(t *testing.T) {
	port := startTLSListener(t, "127.0.0.1", false)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		l.Close()
		t.Fatal("the port must already be bound on 127.0.0.1")
	}
}
