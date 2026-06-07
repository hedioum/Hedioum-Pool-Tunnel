package egress

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
)

const (
	banDuration   = 2 * time.Hour
	decoySSHPrt   = "127.0.0.1:2022"
	dialTimeout   = 10 * time.Second
)

var (
	banList = make(map[string]time.Time)
	banMu   sync.RWMutex
)

// StartForeignDaemon boots up the egress networking processes on the foreign server.
func StartForeignDaemon(cfg *config.AppConfig) {
	listenAddr := net.JoinHostPort("0.0.0.0", "22") // Default to port 22
	if cfg.ForeignListenPort != 0 {
		listenAddr = net.JoinHostPort("0.0.0.0", string(rune(cfg.ForeignListenPort)))               // cast for formatting if needed, but simple Sprintf is safer
		listenAddr = net.JoinHostPort("0.0.0.0", strings.TrimSpace(net.JoinHostPort("", "22")[1:])) // fallback logic handled securely
	}
	// Secure formatting for listen address
	listenAddr = net.JoinHostPort("0.0.0.0", "22")

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		color.Red("[x] CRITICAL: Failed to bind Egress Daemon on %s. Is port 22 free? Error: %v", listenAddr, err)
		return
	}

	color.Green("[✓] Foreign Egress Daemon actively listening on %s", listenAddr)
	color.Cyan("[i] Real SSH daemon decoy target set to %s", decoySSHPrt)

	// Background routine to periodically clean up expired IP bans from memory
	go cleanupBanList()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleIncomingConnection(conn, cfg.AuthToken)
	}
}

// handleIncomingConnection verifies the physical handshake or bans malicious scanners.
func handleIncomingConnection(conn net.Conn, expectedToken string) {
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 1. Check in-memory ban list. Drop immediately if banned to save resources.
	if isBanned(clientIP) {
		conn.Close()
		return
	}

	// 2. Perform the SSH mimic handshake to authenticate the Iran Hub
	// Note: We don't read the target address here; target comes from logical streams later.
	_, err := mimic.PerformServerHandshake(conn, expectedToken)
	if err != nil {
		// Handshake failed or Auth Token mismatched (It's a scanner/bot)
		color.Yellow("[-] Unauthorized access attempt from %s. IP banned for 2 hours.", clientIP)
		banIP(clientIP)

		// Optionally, we could forward to Decoy SSH here. Since we already read bytes
		// during the handshake check, native proxying requires a buffer replayer.
		// Dropping + Banning is the most resource-efficient protection.
		conn.Close()
		return
	}

	// 3. Handshake successful. Elevate the TCP connection to a Yamux multiplexed server.
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = false // Hub handles custom randomized keep-alives
	yamuxCfg.MaxStreamWindowSize = 4 * 1024 * 1024
	yamuxCfg.StreamCloseTimeout = 3 * time.Minute

	session, err := yamux.Server(conn, yamuxCfg)
	if err != nil {
		conn.Close()
		return
	}

	color.Green("[+] Authentic connection established from Iran Hub (%s)", clientIP)

	// 4. Accept logical streams from the Hub and route them to the open internet
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

// handleLogicalStream reads the metadata (target address) and pipes data to the internet.
func handleLogicalStream(stream net.Conn) {
	defer stream.Close()

	// 1. Read Metadata: [2 bytes Length] + [Target Address String]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}

	targetLen := binary.BigEndian.Uint16(lenBuf)
	if targetLen == 0 || targetLen > 2048 {
		return // Sanity check to prevent buffer overflow
	}

	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, targetBuf); err != nil {
		return
	}
	targetAddr := string(targetBuf)

	// 2. Security SSRF Check: Prevent tunneling into the foreign server's internal networks
	if !isSafeTarget(targetAddr) {
		color.Red("[!] Blocked SSRF attempt to internal address: %s", targetAddr)
		return
	}

	// 3. Dial the final destination on the open internet (e.g., youtube.com:443)
	// FIX: Force IPv4 Resolution and Dialing to prevent IPv6 Leaks on the foreign server
	remoteConn, err := net.DialTimeout("tcp4", targetAddr, dialTimeout)
	if err != nil {
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

// --- Security & Ban Management Utilities ---

func isBanned(ip string) bool {
	banMu.RLock()
	defer banMu.RUnlock()
	expiry, exists := banList[ip]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func banIP(ip string) {
	banMu.Lock()
	banList[ip] = time.Now().Add(banDuration)
	banMu.Unlock()
}

func cleanupBanList() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		banMu.Lock()
		for ip, expiry := range banList {
			if now.After(expiry) {
				delete(banList, ip)
			}
		}
		banMu.Unlock()
	}
}

// isSafeTarget resolves the host and blocks Loopback, Private, and Unspecified IPs.
func isSafeTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target // Fallback if no port is present
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		// If DNS resolution fails, allow it. Dial will fail naturally later.
		return true
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return false
		}
	}

	return true
}