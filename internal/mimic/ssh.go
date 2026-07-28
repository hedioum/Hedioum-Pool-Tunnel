package mimic

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
)

const (
	defaultSSHBanner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
	handshakeTimeout = 8 * time.Second
)

// --- Connection Wrappers for Zero-Data-Loss Proxying ---

// RecorderConn intercepts and records all bytes read from the underlying
// connection so a failed handshake can be replayed verbatim to the decoy.
// Recording can be stopped once the peer is authenticated, so the successful
// path does not accumulate the entire session in memory.
type RecorderConn struct {
	net.Conn
	ReadBuf   bytes.Buffer
	recording bool
}

func (r *RecorderConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 && r.recording {
		r.ReadBuf.Write(p[:n])
	}
	return n, err
}

// Stop halts recording (and releases the recorded buffer). Called after a peer
// authenticates so the ongoing high-speed session is not buffered.
func (r *RecorderConn) Stop() {
	r.recording = false
	r.ReadBuf.Reset()
}

// ReplayConn wraps a net.Conn and an io.Reader to replay recorded bytes before
// continuing to read from the socket naturally.
type ReplayConn struct {
	net.Conn
	reader io.Reader
}

func (r *ReplayConn) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

// buildReplayConn combines the recorded buffer and the original socket into a
// seamless stream, so the decoy receives the exact bytes the scanner sent.
func buildReplayConn(conn net.Conn, rec *RecorderConn) net.Conn {
	replayReader := io.MultiReader(bytes.NewReader(rec.ReadBuf.Bytes()), conn)
	return &ReplayConn{Conn: conn, reader: replayReader}
}

// --- Banner Management ---

// GetDynamicSSHBanner extracts the local SSH version to remain indistinguishable
// from a real host; falls back to a sane default.
func GetDynamicSSHBanner() string {
	cmd := exec.Command("ssh", "-V")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && stderr.Len() == 0 {
		return defaultSSHBanner
	}

	output := strings.TrimSpace(stderr.String())
	parts := strings.Split(output, ",")
	if len(parts) > 0 {
		return fmt.Sprintf("SSH-2.0-%s\r\n", strings.TrimSpace(parts[0]))
	}
	return defaultSSHBanner
}

// readBanner safely reads strictly up to the newline character, so it never
// over-reads into the bytes that follow the banner.
func readBanner(conn net.Conn) (string, error) {
	var banner []byte
	buf := make([]byte, 1)
	for i := 0; i < 255; i++ {
		_, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		banner = append(banner, buf[0])
		if buf[0] == '\n' {
			break
		}
	}
	return string(banner), nil
}

// FetchRealSSHBanner connects to the decoy sshd and returns its exact banner
// line. The egress presents this same banner to peers so that a real SSH client
// routed to the decoy still completes key exchange: SSH binds the server banner
// into the KEX hash, so a mismatched mimic banner would break admin logins
// (both password and key auth) on the public port.
func FetchRealSSHBanner(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	return readBanner(conn)
}

// ConsumeDecoyServerBanner reads and discards the SSH banner from the decoy so a
// scanner proxied to it does not receive two banners.
func ConsumeDecoyServerBanner(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{})
	_, err := readBanner(conn)
	return err
}

// --- Handshake Execution ---

// PerformClientHandshake exchanges SSH banners for camouflage and then upgrades
// the connection to an authenticated ChaCha20-Poly1305 stream. The token is the
// pre-shared secret and is never transmitted in the clear.
func PerformClientHandshake(conn net.Conn, token string) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	// 1. Exchange banners (camouflage layer).
	if _, err := conn.Write([]byte(GetDynamicSSHBanner())); err != nil {
		return nil, fmt.Errorf("failed to write client banner: %w", err)
	}
	if _, err := readBanner(conn); err != nil {
		return nil, fmt.Errorf("failed to read server banner: %w", err)
	}

	// 2. Upgrade to the authenticated, encrypted transport.
	sc, err := securestream.ClientHandshake(conn, token)
	if err != nil {
		return nil, fmt.Errorf("secure handshake failed: %w", err)
	}
	return sc, nil
}

// PerformServerHandshake exchanges banners, then authenticates the peer over the
// encrypted transport. On success it returns the SecureConn. On any failure it
// returns a ReplayConn carrying the exact bytes the peer sent, so the caller can
// route the (likely scanner/probe) connection to the SSH decoy. filter provides
// replay protection and may be nil.
// serverBanner is the banner to present; when empty a synthesized banner is used.
// For transparent decoy passthrough it should be the real sshd banner (see
// FetchRealSSHBanner).
func PerformServerHandshake(conn net.Conn, expectedToken string, filter *securestream.ReplayFilter, serverBanner string) (secure net.Conn, replay net.Conn, err error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, conn, err
	}
	defer conn.SetDeadline(time.Time{})

	if serverBanner == "" {
		serverBanner = GetDynamicSSHBanner()
	}

	rec := &RecorderConn{Conn: conn, recording: true}

	// 1. Send our banner, then read + validate the client banner.
	if _, err := conn.Write([]byte(serverBanner)); err != nil {
		return nil, buildReplayConn(conn, rec), fmt.Errorf("failed to write server banner: %w", err)
	}
	clientBanner, err := readBanner(rec)
	if err != nil {
		return nil, buildReplayConn(conn, rec), fmt.Errorf("failed to read client banner: %w", err)
	}
	if !strings.HasPrefix(clientBanner, "SSH-2.0") {
		return nil, buildReplayConn(conn, rec), errors.New("invalid protocol banner signature")
	}

	// 2. Authenticate over the encrypted transport. A wrong PSK (or a probe that
	// is not speaking our protocol) fails the AEAD tag -> route to decoy.
	sc, err := securestream.ServerHandshake(rec, expectedToken, filter)
	if err != nil {
		return nil, buildReplayConn(conn, rec), err
	}

	// 3. Authenticated: stop recording so the session is not buffered.
	rec.Stop()
	return sc, nil, nil
}
