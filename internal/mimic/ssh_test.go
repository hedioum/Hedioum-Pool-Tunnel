package mimic

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
)

// TestHandshakeRoundTripTCP verifies banner exchange + AEAD upgrade + data flow
// over a real TCP connection when both sides share the token.
func TestHandshakeRoundTripTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const token = "integration-shared-secret"
	filter := securestream.NewReplayFilter(0)
	srvErr := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		sc, _, err := PerformServerHandshake(conn, token, filter, "")
		if err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(sc, buf); err != nil {
			srvErr <- err
			return
		}
		_, err = sc.Write(buf) // echo
		srvErr <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sc, err := PerformClientHandshake(conn, token)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := sc.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestWrongTokenRoutesToDecoy verifies the server returns ErrAuth for a bad token
// and the returned ReplayConn still carries the original client banner, so the
// decoy receives the exact bytes the peer sent.
func TestWrongTokenRoutesToDecoy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		err    error
		replay net.Conn
	}
	srvCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		_, replay, err := PerformServerHandshake(conn, "server-token", securestream.NewReplayFilter(0), "")
		srvCh <- result{err: err, replay: replay}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Client uses a different token; drive its handshake in the background since it
	// will block/timeout once the server stops reading.
	go PerformClientHandshake(conn, "client-token")

	select {
	case r := <-srvCh:
		if r.err != securestream.ErrAuth {
			t.Fatalf("expected ErrAuth, got %v", r.err)
		}
		if r.replay == nil {
			t.Fatal("expected a replay conn for the decoy")
		}
		r.replay.SetReadDeadline(time.Now().Add(2 * time.Second))
		head := make([]byte, 8)
		n, _ := io.ReadFull(r.replay, head)
		if !strings.HasPrefix(string(head[:n]), "SSH-2.0") {
			t.Fatalf("replay stream should start with the recorded SSH banner, got %q", head[:n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not return")
	}
}

// TestFetchRealSSHBanner verifies we read the decoy's banner line verbatim.
func TestFetchRealSSHBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const want = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte(want))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()

	got, err := FetchRealSSHBanner(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("banner mismatch: got %q want %q", got, want)
	}
}

// TestServerPresentsMirroredBanner verifies the egress presents exactly the
// banner it was given, so it can byte-match the real sshd for decoy passthrough.
func TestServerPresentsMirroredBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const banner = "SSH-2.0-OpenSSH_9.9p1 MirrorTest\r\n"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Auth will fail (the client below sends nothing valid), but the banner is
		// presented before any authentication.
		PerformServerHandshake(conn, "tok", nil, banner)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got, err := readBanner(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got != banner {
		t.Fatalf("presented banner: got %q want %q", got, banner)
	}
}
