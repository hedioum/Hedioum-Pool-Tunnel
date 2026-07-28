package securestream

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// handshakePair drives both handshakes concurrently over an in-memory pipe.
func handshakePair(t *testing.T, clientTok, serverTok string, filter *ReplayFilter) (*SecureConn, *SecureConn, error) {
	t.Helper()
	c, s := net.Pipe()

	type res struct {
		sc  *SecureConn
		err error
	}
	srvCh := make(chan res, 1)
	go func() {
		sc, err := ServerHandshake(s, serverTok, filter)
		srvCh <- res{sc, err}
	}()

	cli, cerr := ClientHandshake(c, clientTok)
	sr := <-srvCh

	if cerr != nil {
		return nil, nil, cerr
	}
	if sr.err != nil {
		return nil, nil, sr.err
	}
	return cli, sr.sc, nil
}

func TestRoundTrip(t *testing.T) {
	cli, srv, err := handshakePair(t, "shared-secret-token", "shared-secret-token", nil)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// Payload spanning multiple AEAD chunks to exercise framing + partial reads.
	payload := make([]byte, 5*maxChunk+123)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// client -> server
	go func() {
		if _, err := cli.Write(payload); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client->server payload mismatch")
	}

	// server -> client (small message, tiny read buffers to force leftover path)
	msg := []byte("hello from the egress side")
	go func() {
		if _, err := srv.Write(msg); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()
	var assembled []byte
	buf := make([]byte, 7)
	for len(assembled) < len(msg) {
		n, err := cli.Read(buf)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		assembled = append(assembled, buf[:n]...)
	}
	if !bytes.Equal(assembled, msg) {
		t.Fatalf("server->client mismatch: %q", assembled)
	}
}

func TestWrongTokenFailsAuth(t *testing.T) {
	// The egress relies on ServerHandshake returning ErrAuth for a wrong PSK so it
	// can divert to the decoy. (On net.Pipe the client would block once the server
	// stops reading, so we assert on the server side and close to unblock.)
	c, s := net.Pipe()
	srvErr := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(s, "server-token", nil)
		s.Close()
		srvErr <- err
	}()
	go func() {
		if cli, err := ClientHandshake(c, "client-token"); err == nil {
			cli.Close()
		}
		c.Close()
	}()

	select {
	case err := <-srvErr:
		if err != ErrAuth {
			t.Fatalf("expected ErrAuth, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not return in time")
	}
}

func TestReplayFilterRejectsDuplicate(t *testing.T) {
	f := NewReplayFilter(1000)
	salt := make([]byte, saltSize)
	rand.Read(salt)

	if !f.Accept(salt) {
		t.Fatal("first use should be accepted")
	}
	if f.Accept(salt) {
		t.Fatal("replayed salt must be rejected")
	}

	other := make([]byte, saltSize)
	rand.Read(other)
	if !f.Accept(other) {
		t.Fatal("a distinct salt should be accepted")
	}
}

func TestReplayFilterBounded(t *testing.T) {
	f := NewReplayFilter(100)
	for i := 0; i < 1000; i++ {
		salt := make([]byte, saltSize)
		rand.Read(salt)
		f.Accept(salt)
	}
	f.mu.Lock()
	n := len(f.seen)
	f.mu.Unlock()
	if n > 100 {
		t.Fatalf("filter exceeded its size bound: %d", n)
	}
}

// sizeRecorder is a minimal net.Conn that only records the length of each Write.
type sizeRecorder struct {
	net.Conn
	sizes []int
}

func (s *sizeRecorder) Write(p []byte) (int, error) {
	s.sizes = append(s.sizes, len(p))
	return len(p), nil
}

// TestPaddingVariesFrameSize verifies that identical plaintext produces
// varying on-wire frame sizes, so the warm-up pool connections cannot be
// fingerprinted by size.
func TestPaddingVariesFrameSize(t *testing.T) {
	rec := &sizeRecorder{}
	sc := newSecureConn(rec)
	aead, err := chacha20poly1305.New(make([]byte, keySize))
	if err != nil {
		t.Fatal(err)
	}
	sc.wAEAD = aead

	for i := 0; i < 64; i++ {
		if _, err := sc.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	uniq := map[int]bool{}
	minSize := 1 << 30
	for _, s := range rec.sizes {
		uniq[s] = true
		if s < minSize {
			minSize = s
		}
	}
	if len(uniq) < 2 {
		t.Fatalf("expected varied frame sizes from padding, got sizes %v", rec.sizes)
	}
	// Even the smallest frame carries the two AEAD headers/tags for a 1-byte payload.
	if wantMin := lenHdrLen + tagSize + 1 + tagSize; minSize < wantMin {
		t.Fatalf("min frame size %d below AEAD overhead floor %d", minSize, wantMin)
	}
}
