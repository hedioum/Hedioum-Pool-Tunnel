package egress

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/proxyproto"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tlscert"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

const (
	dialTimeout = 10 * time.Second

	egressIPv4 = "ipv4"
	egressIPv6 = "ipv6"
	egressDual = "dual"
)

const tlsCertDir = "/etc/hedioum/tls"

// Egress dial policy, set once at StartForeignDaemon. Default is IPv4-only egress
// so a misconfiguration can never leak the server's IPv6 identity.
var (
	egressMode   = egressIPv4
	egressBindIP net.IP // optional source IP to bind
)

// StartForeignDaemon boots the egress: one camouflage listener per configured
// mimic (SSH, TLS, ...), all feeding the same tunnel core.
func StartForeignDaemon(cfg *config.AppConfig) {
	// Apply the egress dial policy (how we reach the open internet).
	if cfg.EgressIPMode != "" {
		egressMode = cfg.EgressIPMode
	}
	if cfg.EgressBindIP != "" {
		egressBindIP = net.ParseIP(cfg.EgressBindIP)
	}
	slog.Info("egress starting", "egress_mode", egressMode, "mimics", len(cfg.Mimics), "decoy_style", cfg.DecoyStyle, "domain", cfg.Domain)

	// Reverse tunnel: dial out to the Iran hub (see reverse.go). In reverse-only mode
	// no inbound listener is opened.
	StartReverseDialOut(cfg)
	if cfg.ReverseOnly {
		slog.Info("egress running in reverse-only mode (no inbound listeners)")
		sysutil.WaitForTerminationSignal()
		return
	}

	// One certificate manager for the whole daemon: a real Let's Encrypt cert (ACME)
	// when a domain is configured and points here, otherwise self-signed. Shared by
	// all TLS-family listeners so there is a single ACME account/cache.
	certMgr, err := tlscert.NewCertManager(tlsCertDir, cfg.Domain, cfg.ACMEEmail, cfg.Domain)
	if err != nil {
		slog.Error("failed to initialize certificate manager", "err", err)
		return
	}

	// One replay filter is shared across listeners (SSH salts and TLS nonces are
	// distinct high-entropy values).
	replayFilter := securestream.NewReplayFilter(0)

	for _, ml := range cfg.Mimics {
		go startMimicListener(cfg, ml, replayFilter, certMgr)
	}

	// Plaintext :80 server: serves the ACME HTTP-01 challenge, redirects to HTTPS
	// when a domain is set, and otherwise answers with the persona's default page —
	// so the box looks like an ordinary web host to IP-reputation scanners.
	if cfg.HTTPDecoyPort > 0 {
		go startHTTPServer(cfg.HTTPDecoyPort, certMgr, cfg)
	}

	sysutil.WaitForTerminationSignal() // block until terminated (see helper)
}

// startHTTPServer runs the plaintext :80 endpoint: ACME HTTP-01 challenge handling,
// then either a 301 redirect to HTTPS (domain configured) or the persona's default
// page (no domain).
func startHTTPServer(port int, certMgr *tlscert.CertManager, cfg *config.AppConfig) {
	var fallback http.Handler
	if cfg.Domain != "" {
		fallback = mimic.RedirectHTTPSHandler(cfg.Domain)
	} else {
		fallback = mimic.NewDecoyProfile(cfg.AuthToken).WebDefaultHTTPHandler(cfg.DecoyStyle)
	}
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           certMgr.HTTPChallengeHandler(fallback),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("HTTP :80 active", "addr", srv.Addr, "style", cfg.DecoyStyle, "acme", certMgr.ACMEConfigured())
	if err := srv.ListenAndServe(); err != nil {
		// Something already owns :80 (a real web server) — that is fine, leave it be.
		slog.Warn("HTTP :80 not served", "addr", srv.Addr, "err", err)
	}
}

// proxyHeaderTimeout bounds how long a connection from the front proxy may take to send
// its PROXY header.
const proxyHeaderTimeout = 5 * time.Second

// startMimicListener binds one port and serves it with the given mimic.
func startMimicListener(cfg *config.AppConfig, ml config.MimicListener, filter *securestream.ReplayFilter, certMgr *tlscert.CertManager) {
	m, err := buildServerMimic(cfg, ml, filter, certMgr)
	if err != nil {
		slog.Error("failed to build mimic", "type", ml.Type, "err", err)
		return
	}

	// Dual-stack listen (":port") so an Iran hub can reach us over IPv4 or IPv6, unless a
	// front proxy is configured (cfg.ListenBind, e.g. 127.0.0.1).
	listenAddr := net.JoinHostPort(cfg.ListenBind, strconv.Itoa(ml.Port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("failed to bind mimic listener", "type", ml.Type, "addr", listenAddr, "err", err)
		return
	}
	// Behind a front proxy that sends the PROXY protocol, take the real client address
	// from its header and drop anything that did not come through the proxy. The SSH
	// mimic is not a TLS service a proxy can route by SNI, so it is left alone.
	requireProxy := cfg.ProxyProtocol && ml.Type != "ssh"
	slog.Info("mimic listener active", "type", ml.Type, "addr", listenAddr, "proxy_protocol", requireProxy)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		if !requireProxy {
			go handleIncomingConnection(conn, m, ml.Type)
			continue
		}
		go func(conn net.Conn) {
			c, err := proxyproto.Accept(conn, proxyHeaderTimeout)
			if err != nil {
				slog.Debug("dropped a connection without a PROXY header", "type", ml.Type, "err", err)
				conn.Close()
				return
			}
			handleIncomingConnection(c, m, ml.Type)
		}(conn)
	}
}

// buildServerMimic constructs the server-side camouflage for a listener.
func buildServerMimic(cfg *config.AppConfig, ml config.MimicListener, filter *securestream.ReplayFilter, certMgr *tlscert.CertManager) (mimic.ServerMimic, error) {
	// Per-install decoy identity (server version / date / ETag), seeded from the
	// secret token so the web decoy is not byte-identical across the fleet.
	decoy := mimic.NewDecoyProfile(cfg.AuthToken)
	switch ml.Type {
	case "tls", "smtps", "imaps", "https-alt":
		// Implicit TLS: the wire is TLS from the first byte (like HTTPS/IMAPS/SMTPS).
		// smtps/imaps/https-alt are the same mimic as tls, just on their conventional
		// ports. These present the real (ACME) cert when a domain is configured.
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy, // "" -> built-in persona page
			Decoy:          decoy.WebDecoyFor(cfg.DecoyStyle),
		}, nil
	case "docker":
		// Container-registry persona on :5000 — implicit TLS; an unauthorized probe
		// gets a docker/distribution Registry v2 API challenge (401 + registry marker).
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          mimic.ServeDockerRegistry,
		}, nil
	case "grafana":
		// Grafana persona on :3000 — implicit TLS; an unauthorized probe gets the
		// default Grafana login + the unauthenticated /api/health JSON.
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          mimic.ServeGrafana,
		}, nil
	case "prometheus":
		// Prometheus persona on :9090 — implicit TLS; an unauthorized probe gets the
		// real /-/healthy, /metrics and /api/v1 fingerprints.
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          mimic.ServePrometheus,
		}, nil
	case "cpanel", "whm", "webmail":
		// cpsrvd panel personas on :2083 / :2087 / :2096 — implicit TLS; an unauthorized
		// probe gets the matching cPanel/WHM/Webmail login (same cpsrvd template).
		cpsrvdDecoy := map[string]func(net.Conn){
			"cpanel": mimic.ServeCPanel, "whm": mimic.ServeWHM, "webmail": mimic.ServeWebmail,
		}[ml.Type]
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          cpsrvdDecoy,
		}, nil
	case "directadmin":
		// The DirectAdmin panel persona on :2222. It presents the real (ACME) cert
		// when a domain is configured — exactly like a well-run panel with a hostname
		// certificate — and falls back to self-signed otherwise (also authentic for a
		// default DirectAdmin install). The decoy for unauthorized probes is the
		// DirectAdmin login; an operator running a real panel can set ml.Decoy to
		// proxy to it for perfect fidelity.
		return &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          mimic.ServeDirectAdminPanel,
		}, nil
	case "smtp", "imap", "postgres", "mysql":
		// STARTTLS family: a plaintext protocol prologue upgrades to the same TLS
		// mimic. smtp/imap look like a mail server negotiating STARTTLS; postgres/
		// mysql look like a database negotiating SSL, then TLS.
		return &mimic.StartTLSMimic{Proto: ml.Type, TLS: &mimic.TLSMimic{
			Token:          cfg.AuthToken,
			Filter:         filter,
			GetCertificate: certMgr.GetCertificate,
			NextProtos:     certMgr.NextProtos(),
			DecoyAddr:      ml.Decoy,
			Decoy:          decoy.WebDecoyFor(cfg.DecoyStyle),
		}}, nil
	default: // "ssh"
		sshDecoy := ml.Decoy
		if sshDecoy == "" {
			sshDecoy = fmt.Sprintf("127.0.0.1:%d", cfg.DecoyPort)
		}
		// Mirror the real sshd banner so a genuine SSH client routed to the decoy
		// completes key exchange; kept fresh across boot races / sshd upgrades.
		banner := newDecoyBannerMirror(sshDecoy)
		return &mimic.SSHMimic{Token: cfg.AuthToken, Filter: filter, DecoyAddr: sshDecoy, Banner: banner.get}, nil
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
		slog.Info("mirroring decoy SSH banner")
	} else {
		slog.Warn("decoy SSH banner not available yet; retrying in background", "decoy", addr)
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
			slog.Info("mirroring decoy SSH banner")
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

// handleIncomingConnection runs the mimic handshake, diverts unauthorized probes
// to the mimic's decoy, or establishes the Yamux tunnel.
// label is the configured listener type (ssh/tls/smtp/imap/smtps/imaps); it is
// used for logging so implicit-TLS variants are distinguished from plain tls,
// which share the same underlying mimic and Name().
func handleIncomingConnection(conn net.Conn, m mimic.ServerMimic, label string) {
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 1. Camouflage + authenticate. On failure we receive a replay conn carrying
	// the exact bytes the peer sent, to forward to the decoy backend.
	secureConn, replayConn, err := m.Accept(conn)
	if err != nil {
		// A wrong credential, a replayed handshake, or a probe not speaking our
		// protocol. Route it to the decoy so the port looks like a real service
		// (no ban, uniform behavior).
		if errors.Is(err, securestream.ErrAuth) {
			slog.Debug("unauthorized/replayed probe; routing to decoy", "client_ip", clientIP, "mimic", label)
		}
		go m.ProxyDecoy(replayConn)
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

	slog.Info("authentic hub connection established", "client_ip", clientIP, "mimic", label)

	// 3. Accept logical streams from the Hub and route them to the open internet
	go handleYamuxSession(session)
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
	case tunproto.StreamSpeedtest:
		handleSpeedtestStream(stream)
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
			slog.Warn("blocked SSRF attempt (TCP)", "target", targetAddr, "err", err)
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

// errBlockedTarget marks a target rejected for pointing at a non-global address
// (SSRF attempt), as opposed to an ordinary resolution/dial failure.
var errBlockedTarget = errors.New("blocked non-global target")

// vetted resolves host at most once to a safe, dialable IP of the family allowed
// by the egress mode. It single-sources the SSRF policy for both TCP and UDP:
// dialing the resolved IP (rather than re-resolving) closes the DNS-rebinding
// TOCTOU, and it fails closed on resolution errors. Returns the IP and whether it
// is IPv4.
func vetted(host string) (net.IP, bool, error) {
	// IP literal.
	if ip := net.ParseIP(host); ip != nil {
		if !isDialableIP(ip) {
			return nil, false, fmt.Errorf("%w %s", errBlockedTarget, host)
		}
		return pickFamily([]net.IP{ip}, host)
	}

	// Hostname: resolve once; reject the whole target if ANY resolved address is
	// non-global (defends against split-horizon answers mixing public + internal).
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, false, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if !isDialableIP(ip) {
			return nil, false, fmt.Errorf("%w %s (%s)", errBlockedTarget, host, ip)
		}
	}
	return pickFamily(ips, host)
}

// pickFamily selects a vetted IP honoring the egress family mode. In "dual" and
// the default "ipv4" mode IPv4 is preferred; "ipv6" forces IPv6.
func pickFamily(ips []net.IP, host string) (net.IP, bool, error) {
	var v4, v6 net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if v4 == nil {
				v4 = ip4
			}
		} else if v6 == nil {
			v6 = ip
		}
	}
	switch egressMode {
	case egressIPv6:
		if v6 != nil {
			return v6, false, nil
		}
		return nil, false, fmt.Errorf("no IPv6 address for %s", host)
	case egressDual:
		if v4 != nil {
			return v4, true, nil
		}
		if v6 != nil {
			return v6, false, nil
		}
		return nil, false, fmt.Errorf("no dialable address for %s", host)
	default: // ipv4
		if v4 != nil {
			return v4, true, nil
		}
		return nil, false, fmt.Errorf("no IPv4 address for %s", host)
	}
}

// bindAddrTCP returns the source address to bind, if egressBindIP matches family.
func bindAddrTCP(isV4 bool) *net.TCPAddr {
	if egressBindIP != nil && (egressBindIP.To4() != nil) == isV4 {
		return &net.TCPAddr{IP: egressBindIP}
	}
	return nil
}

// safeDialTarget vets the TCP target and dials the exact vetted IP.
func safeDialTarget(target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	ip, isV4, err := vetted(host)
	if err != nil {
		return nil, err
	}
	network := "tcp6"
	if isV4 {
		network = "tcp4"
	}
	d := net.Dialer{Timeout: dialTimeout, LocalAddr: bindAddrTCP(isV4)}
	return d.Dial(network, net.JoinHostPort(ip.String(), port))
}

// safeDialUDP vets the UDP target and returns a connected UDP socket to the exact
// vetted IP (same SSRF policy as TCP; connected so only the target can reply).
func safeDialUDP(target string) (*net.UDPConn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	ip, isV4, err := vetted(host)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}
	network := "udp6"
	if isV4 {
		network = "udp4"
	}
	var laddr *net.UDPAddr
	if egressBindIP != nil && (egressBindIP.To4() != nil) == isV4 {
		laddr = &net.UDPAddr{IP: egressBindIP}
	}
	return net.DialUDP(network, laddr, &net.UDPAddr{IP: ip, Port: p})
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
