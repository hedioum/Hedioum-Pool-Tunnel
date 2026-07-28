package egress

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

const (
	decoySSHPrt = "127.0.0.1:2022"
	dialTimeout = 10 * time.Second
)

// StartForeignDaemon boots up the egress networking processes on the foreign server.
func StartForeignDaemon(cfg *config.AppConfig) {
	// Dynamically bind to the configured port or fallback to 22
	listenPort := 22
	if cfg.ForeignListenPort != 0 {
		listenPort = cfg.ForeignListenPort
	}
	listenAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		color.Red("[x] CRITICAL: Failed to bind Egress Daemon on %s. Is port %d free? Error: %v", listenAddr, listenPort, err)
		return
	}

	color.Green("[✓] Foreign Egress Daemon actively listening on %s", listenAddr)
	color.Cyan("[i] Real SSH daemon decoy target set to %s", decoySSHPrt)

	// Mirror the real sshd banner so a genuine SSH client (password or key) routed
	// to the decoy still completes key exchange on the public port. Kept fresh so
	// it survives boot races (sshd not up yet) and sshd upgrades.
	banner := newDecoyBannerMirror(decoySSHPrt)

	// Bounded, TTL'd replay protection for the authentication handshake.
	replayFilter := securestream.NewReplayFilter(0)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleIncomingConnection(conn, cfg.AuthToken, replayFilter, banner.get())
	}
}

// decoyBannerMirror holds the real sshd banner and keeps it up to date. SSH binds
// the server banner into its key-exchange hash, so the egress must present the
// exact banner the decoy sshd will use, or admin logins through the decoy break.
type decoyBannerMirror struct {
	v atomic.Value // string
}

func newDecoyBannerMirror(addr string) *decoyBannerMirror {
	m := &decoyBannerMirror{}
	m.v.Store("")
	// Best-effort synchronous first fetch so the common case (sshd already up) has
	// the banner ready before we accept connections.
	if b, err := mimic.FetchRealSSHBanner(addr); err == nil && b != "" {
		m.v.Store(b)
		color.Cyan("[i] Mirroring decoy SSH banner for transparent admin access.")
	} else {
		color.Yellow("[-] Decoy SSH banner not available yet from %s; retrying in the background (admin SSH via the decoy may fail until then).", addr)
	}
	go m.refreshLoop(addr)
	return m
}

// get returns the current mirrored banner ("" -> the handshake will synthesize one).
func (m *decoyBannerMirror) get() string {
	s, _ := m.v.Load().(string)
	return s
}

func (m *decoyBannerMirror) refreshLoop(addr string) {
	// Retry quickly until we have a banner (covers sshd coming up after us on boot).
	for m.get() == "" {
		time.Sleep(3 * time.Second)
		if b, err := mimic.FetchRealSSHBanner(addr); err == nil && b != "" {
			m.v.Store(b)
			color.Cyan("[i] Mirroring decoy SSH banner for transparent admin access.")
			break
		}
	}
	// Then refresh slowly to follow sshd restarts/upgrades.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if b, err := mimic.FetchRealSSHBanner(addr); err == nil && b != "" {
			m.v.Store(b)
		}
	}
}

// handleIncomingConnection authenticates the peer over the encrypted handshake,
// diverts unauthorized probes to the decoy, or establishes the Yamux tunnel.
func handleIncomingConnection(conn net.Conn, expectedToken string, filter *securestream.ReplayFilter, serverBanner string) {
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 1. Exchange banners + authenticate over the encrypted transport. On failure
	// we receive a ReplayConn carrying the exact bytes the peer sent.
	secureConn, replayConn, err := mimic.PerformServerHandshake(conn, expectedToken, filter, serverBanner)
	if err != nil {
		// A wrong PSK, a replayed handshake, or a probe that is not speaking our
		// protocol. Route it to the real OpenSSH decoy so the server is
		// indistinguishable from an ordinary SSH host (no ban, uniform behavior).
		if errors.Is(err, securestream.ErrAuth) {
			color.Yellow("[-] Unauthorized/replayed probe from %s. Routing to Decoy SSH.", clientIP)
		}
		go proxyToDecoy(replayConn)
		return
	}

	// 2. Elevate the authenticated, decrypted connection to a Yamux server.
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = false // Hub handles custom randomized keep-alives
	yamuxCfg.MaxStreamWindowSize = 4 * 1024 * 1024
	yamuxCfg.StreamCloseTimeout = 3 * time.Minute

	session, err := yamux.Server(secureConn, yamuxCfg)
	if err != nil {
		secureConn.Close()
		return
	}

	color.Green("[+] Authentic connection established from Iran Hub (%s)", clientIP)

	// 3. Accept logical streams from the Hub and route them to the open internet
	go handleYamuxSession(session)
}

// proxyToDecoy silently bridges unauthorized connections to the local OpenSSH daemon.
func proxyToDecoy(clientConn net.Conn) {
	defer clientConn.Close()

	// Dial the real SSH daemon we moved to port 2022
	decoyConn, err := net.DialTimeout("tcp", decoySSHPrt, 5*time.Second)
	if err != nil {
		return
	}
	defer decoyConn.Close()

	// --- DECOY BANNER CONSUMPTION ---
	// The client has already received a fake SSH banner from our mimic handshake.
	// The real SSH daemon (Decoy) will also send its own banner as soon as we connect.
	// If we pipe immediately, the client gets TWO banners and crashes with "Bad packet length".
	// Therefore, we must silently consume and discard the decoy's banner first.
	_ = mimic.ConsumeDecoyServerBanner(decoyConn)

	// Pipe traffic bidirectionally so the scanner interacts with real SSH
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(decoyConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, decoyConn)
		errChan <- err
	}()

	<-errChan
}

// handleYamuxSession accepts individual user streams multiplexed over the single physical link.
func handleYamuxSession(session *yamux.Session) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// Physical connection died or closed
			session.Close()
			return
		}

		go handleLogicalStream(stream)
	}
}

// handleLogicalStream dispatches a logical stream on its leading type byte:
// TCP CONNECT is piped to the internet; UDP ASSOCIATE is relayed as datagrams.
func handleLogicalStream(stream net.Conn) {
	defer stream.Close()

	streamType, err := tunproto.ReadStreamType(stream)
	if err != nil {
		return
	}
	switch streamType {
	case tunproto.StreamTCP:
		handleTCPStream(stream)
	case tunproto.StreamUDP:
		handleUDPStream(stream)
	default:
		// Unknown stream type: drop.
	}
}

// handleTCPStream reads the target address and pipes data to the internet.
func handleTCPStream(stream net.Conn) {
	targetAddr, err := tunproto.ReadTCPTarget(stream)
	if err != nil {
		return
	}

	// SSRF-safe dial: resolve once, vet the address, and dial that exact IP
	// (no second lookup -> no DNS rebinding). Fails closed on resolution errors.
	remoteConn, err := safeDialTarget(targetAddr)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			color.Red("[!] Blocked SSRF attempt to %s (%v)", targetAddr, err)
		}
		return
	}
	defer remoteConn.Close()

	// 4. Pipe traffic bidirectionally
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(remoteConn, stream)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(stream, remoteConn)
		errChan <- err
	}()

	<-errChan
}

// handleUDPStream relays a UDP association's datagrams to the internet.
// (Implemented in the UDP-egress step of Milestone 2.)
func handleUDPStream(stream net.Conn) {
	// Placeholder until the UDP relay + NAT table land; drop for now.
}

// errBlockedTarget marks a target rejected for pointing at a non-global address
// (SSRF attempt), as opposed to an ordinary resolution/dial failure.
var errBlockedTarget = errors.New("blocked non-global target")

// safeDialTarget resolves the target host at most once, rejects any address that
// is not a global unicast internet address, and dials the vetted IP directly.
// Dialing the resolved IP (rather than re-resolving the hostname) closes the
// DNS-rebinding TOCTOU. Resolution failures fail closed.
func safeDialTarget(target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}

	// IP literal: vet and dial directly.
	if ip := net.ParseIP(host); ip != nil {
		if !isDialableIP(ip) {
			return nil, fmt.Errorf("%w %s", errBlockedTarget, host)
		}
		return net.DialTimeout("tcp4", net.JoinHostPort(host, port), dialTimeout)
	}

	// Hostname: resolve once, then dial a vetted IPv4 literal.
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var chosen net.IP
	for _, ip := range ips {
		// Reject the whole target if ANY resolved address is non-global (defends
		// against split-horizon answers mixing a public and an internal IP).
		if !isDialableIP(ip) {
			return nil, fmt.Errorf("%w %s (%s)", errBlockedTarget, host, ip)
		}
		if chosen == nil {
			if ip4 := ip.To4(); ip4 != nil {
				chosen = ip4
			}
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("no dialable IPv4 address for %s", host)
	}
	return net.DialTimeout("tcp4", net.JoinHostPort(chosen.String(), port), dialTimeout)
}

// isDialableIP reports whether ip is a public, global unicast internet address
// safe to dial. It blocks loopback, link-local (incl. 169.254.169.254 cloud
// metadata), multicast, unspecified, RFC 1918 private, and RFC 6598 CGNAT
// (100.64.0.0/10, used by some cloud metadata endpoints) addresses.
func isDialableIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false // loopback, link-local, multicast, unspecified
	}
	if ip.IsPrivate() {
		return false // 10/8, 172.16/12, 192.168/16, fc00::/7
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false // 100.64.0.0/10 CGNAT / shared address space
	}
	return true
}
