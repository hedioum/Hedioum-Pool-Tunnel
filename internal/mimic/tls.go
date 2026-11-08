package mimic

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	utls "github.com/refraction-networking/utls"
)

// TLSMimic disguises the tunnel as an HTTPS server: a real TLS handshake provides
// the single crypto layer, and a channel-bound token auth (tlsauth.go) proves the
// peer without sending the token and without a second encryption layer. The
// certificate is chosen per-handshake by GetCertificate — a real Let's Encrypt cert
// (ACME) when a domain is configured, otherwise self-signed. The auth binds to the
// certificate actually served on THIS handshake, so ACME renewal (which rotates the
// cert) never breaks authentication. Unauthenticated peers (browsers/probes) are
// served a plausible response, so the port looks like an ordinary web host / panel.
type TLSMimic struct {
	Token string
	// ExtraTokens are further tokens this listener accepts (the hub's shared reverse
	// listener, where one SNI serves several foreign nodes). The index of the token
	// that authenticated a connection (0 = Token, i = ExtraTokens[i-1]) is available
	// from MatchedToken on the connection Accept returns.
	ExtraTokens []string
	Filter      *securestream.ReplayFilter
	// GetCertificate selects the server certificate for each ClientHello (required).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// NextProtos is the ALPN list to advertise (nil -> h2,http/1.1). When ACME is
	// active it must include "acme-tls/1" so TLS-ALPN-01 challenges succeed on :443.
	NextProtos []string
	DecoyAddr  string         // web backend for unauth peers; "" uses Decoy/built-in
	Decoy      func(net.Conn) // built-in decoy writer; nil -> ServeWebDecoy (Apache)
}

func (m *TLSMimic) Accept(conn net.Conn) (net.Conn, net.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Capture the fingerprint of the leaf certificate actually served on this
	// handshake, so the channel-bound auth binds to it (works for self-signed AND
	// rotating ACME certs alike).
	var servedFP [32]byte
	var haveFP bool
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: m.nextProtos(),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := m.GetCertificate(hello)
			if err == nil && c != nil && len(c.Certificate) > 0 {
				servedFP = sha256.Sum256(c.Certificate[0])
				haveFP = true
			}
			return c, err
		},
	}
	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		// Not even a valid TLS ClientHello; nothing believable to serve.
		return nil, conn, err
	}
	_ = conn.SetDeadline(time.Time{})

	// Record the decrypted inner bytes so a non-client can be replayed to the decoy;
	// read the channel-bound auth through the recorder.
	rec := &RecorderConn{Conn: tlsConn, recording: true}
	if !haveFP {
		// No usable certificate was served (e.g. an ACME challenge handshake). Treat
		// as unauthenticated and route to the decoy.
		return nil, buildReplayConn(tlsConn, rec), securestream.ErrAuth
	}
	matched, err := serverVerifyTLSAny(tlsConn, rec, m.tokens(), servedFP, m.Filter)
	if err != nil {
		return nil, buildReplayConn(tlsConn, rec), err // ErrAuth -> decoy
	}
	rec.matched = matched
	rec.Stop()
	return rec, nil, nil // yamux runs directly over the TLS conn (single crypto layer)
}

// tokens is every token this listener accepts, Token first.
func (m *TLSMimic) tokens() []string {
	if len(m.ExtraTokens) == 0 {
		return []string{m.Token}
	}
	return append([]string{m.Token}, m.ExtraTokens...)
}

func (m *TLSMimic) nextProtos() []string {
	if len(m.NextProtos) > 0 {
		return m.NextProtos
	}
	// Advertise HTTP/1.1 only: the built-in decoys speak HTTP/1.1, so negotiating h2
	// would leave a real browser/probe with an unparseable reply (empty page). The
	// tunnel client ignores ALPN (it sends the channel-bound auth, not HTTP).
	return []string{"http/1.1"}
}

// ProxyDecoy serves an unauthenticated peer a believable response — a local backend
// if configured (e.g. a real DirectAdmin panel for pixel-perfect fidelity),
// otherwise the built-in Decoy page (or the Apache default if none is set).
func (m *TLSMimic) ProxyDecoy(replay net.Conn) {
	defer replay.Close()
	if m.DecoyAddr != "" {
		if backend, err := net.DialTimeout("tcp", m.DecoyAddr, 5*time.Second); err == nil {
			defer backend.Close()
			errCh := make(chan error, 2)
			go func() { _, e := io.Copy(backend, replay); errCh <- e }()
			go func() { _, e := io.Copy(replay, backend); errCh <- e }()
			<-errCh
			return
		}
		// backend down: fall through to the built-in page so we still answer plausibly.
	}
	if m.Decoy != nil {
		m.Decoy(replay)
		return
	}
	ServeWebDecoy(replay)
}

func (m *TLSMimic) Name() string { return "tls" }

// TLSClient is the client side of the TLS mimic. It uses uTLS to present a real
// browser's ClientHello (defeating JA3 fingerprinting) and pins the server cert
// TOFU (warn-only; the token auth is the real gate).
type TLSClient struct {
	Token      string
	ServerName string    // SNI
	Pin        *[32]byte // if set, warn on mismatch
	SavePin    func([32]byte)
}

func (c *TLSClient) Dial(conn net.Conn) (net.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	cfg := &utls.Config{ServerName: c.ServerName, InsecureSkipVerify: true}
	uconn := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	state := uconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("tls: server presented no certificate")
	}
	certFP := sha256.Sum256(state.PeerCertificates[0].Raw)

	if c.Pin != nil && *c.Pin != certFP {
		slog.Warn("TLS cert fingerprint changed (possible MITM); token auth still applies", "server", c.ServerName)
	} else if c.Pin == nil && c.SavePin != nil {
		c.SavePin(certFP) // TOFU: remember on first connect
	}

	if err := clientProveTLS(uconn, c.Token, certFP); err != nil {
		return nil, err
	}
	return uconn, nil
}

func (c *TLSClient) Name() string { return "tls" }
