package mimic

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
)

// runAuth drives client+server auth over a pipe with the given tokens/fingerprints.
func runAuth(t *testing.T, clientTok, serverTok string, clientFP, serverFP [32]byte, filter *securestream.ReplayFilter) (clientErr, serverErr error) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	s.SetDeadline(time.Now().Add(3 * time.Second))

	sErr := make(chan error, 1)
	go func() { sErr <- serverVerifyTLS(s, s, serverTok, serverFP, filter) }()
	clientErr = clientProveTLS(c, clientTok, clientFP)
	serverErr = <-sErr
	return
}

func TestTLSAuthSuccess(t *testing.T) {
	fp := [32]byte{1, 2, 3}
	ce, se := runAuth(t, "tok", "tok", fp, fp, securestream.NewReplayFilter(0))
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
}

func TestTLSAuthWrongToken(t *testing.T) {
	fp := [32]byte{9}
	_, se := runAuth(t, "client-tok", "server-tok", fp, fp, nil)
	if !errors.Is(se, securestream.ErrAuth) {
		t.Fatalf("server err = %v, want ErrAuth", se)
	}
}

// A MITM presents a different cert: the client binds to certFP_A, the real server
// verifies against certFP_B -> reject, even with the correct token.
func TestTLSAuthCertMismatchRejected(t *testing.T) {
	fpClient := [32]byte{0xAA}
	fpServer := [32]byte{0xBB}
	_, se := runAuth(t, "tok", "tok", fpClient, fpServer, nil)
	if !errors.Is(se, securestream.ErrAuth) {
		t.Fatalf("server should reject cert mismatch, got %v", se)
	}
}

func TestTLSAuthNonMagicIsDecoy(t *testing.T) {
	// A browser/probe sends HTTP, not our magic -> server returns ErrAuth (-> decoy).
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	s.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
	if err := serverVerifyTLS(s, s, "tok", [32]byte{}, nil); !errors.Is(err, securestream.ErrAuth) {
		t.Fatalf("HTTP probe should be ErrAuth, got %v", err)
	}
}

func TestTLSAuthReplayRejected(t *testing.T) {
	fp := [32]byte{7}
	filter := securestream.NewReplayFilter(0)
	// First handshake succeeds.
	if ce, se := runAuth(t, "tok", "tok", fp, fp, filter); ce != nil || se != nil {
		t.Fatalf("first handshake failed: client=%v server=%v", ce, se)
	}
	// A DIFFERENT client nonce is fresh, so a legit second handshake still works;
	// replay protection is on the nonce, exercised directly:
	nonce := []byte("0123456789abcdef")
	if !filter.Accept(nonce) {
		t.Fatal("fresh nonce should be accepted")
	}
	if filter.Accept(nonce) {
		t.Fatal("replayed nonce must be rejected")
	}
}

func TestServerVerifyTLSAnyPicksMatchingToken(t *testing.T) {
	var fp [32]byte
	fp[0] = 7
	tokens := []string{"token-a", "token-b", "token-c"}
	for want, tok := range tokens {
		c1, c2 := net.Pipe()
		errCh := make(chan error, 1)
		go func() { errCh <- clientProveTLS(c1, tok, fp) }()
		got, err := serverVerifyTLSAny(c2, c2, tokens, fp, nil)
		if err != nil || got != want {
			t.Fatalf("token %q: got index %d err %v, want %d", tok, got, err, want)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("client rejected the ack for %q: %v", tok, err)
		}
		c1.Close()
		c2.Close()
	}
}

func TestServerVerifyTLSAnyRejectsUnknownToken(t *testing.T) {
	var fp [32]byte
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = clientProveTLS(c1, "stranger", fp) }()
	if got, err := serverVerifyTLSAny(c2, c2, []string{"token-a", "token-b"}, fp, nil); err == nil || got != -1 {
		t.Fatalf("unknown token accepted: index %d err %v", got, err)
	}
}
