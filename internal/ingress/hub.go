package ingress

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pool"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

// StartIranHub initializes the SOCKS5 listeners and dynamically scaling connection
// pools for all configured foreign egress nodes.
func StartIranHub(cfg *config.AppConfig) {
	hubManager := pool.NewHubManager()

	for _, node := range cfg.ForeignNodes {
		// 1. Configure optimized Yamux settings for high-latency, high-throughput WAN links
		yamuxCfg := yamux.DefaultConfig()

		// Disable built-in predictable keep-alive to avoid DPI time-based pattern recognition.
		// We will implement a custom, randomized heartbeat.
		yamuxCfg.EnableKeepAlive = false

		// Increase window size to 4MB to prevent TCP window bottlenecks on long-distance links
		yamuxCfg.MaxStreamWindowSize = 4 * 1024 * 1024
		// Allow larger buffer to accommodate high-speed bursts (e.g., streaming video chunks)
		yamuxCfg.StreamCloseTimeout = 3 * time.Minute

		nodeCopy := node // Create a local copy for the closure

		// 2. Define the dialing and physical handshake procedure for this foreign node
		dialerFunc := func() (*yamux.Session, error) {
			// JoinHostPort handles IPv6 literals correctly (brackets), unlike "%s:%d".
			targetAddr := net.JoinHostPort(nodeCopy.TargetIP, strconv.Itoa(nodeCopy.TargetPort))

			// Dial the physical TCP connection
			conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}

			// Exchange SSH banners for camouflage, then upgrade to the authenticated
			// ChaCha20-Poly1305 transport. The token is the pre-shared key and is
			// never sent in the clear; it also keys the AEAD, so a passive observer
			// sees only random salts followed by ciphertext.
			secureConn, err := mimic.PerformClientHandshake(conn, nodeCopy.AuthToken)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("secure handshake failed: %w", err)
			}

			// Wrap the authenticated, encrypted connection in a Yamux client session
			session, err := yamux.Client(secureConn, yamuxCfg)
			if err != nil {
				secureConn.Close()
				return nil, err
			}

			// 4. Launch a custom, randomized Keep-Alive heartbeat to evade DPI periodicity checks
			go func(s *yamux.Session) {
				for {
					if s.IsClosed() {
						return // Stop pinging if the physical session dies
					}
					// Randomize interval between 20 and 45 seconds
					randomDelay := time.Duration(rand.Intn(26)+20) * time.Second
					time.Sleep(randomDelay)

					// Send a silent Yamux ping over the physical channel
					if _, err := s.Ping(); err != nil {
						return
					}
				}
			}(session)

			return session, nil
		}

		// 5. Register the auto-scaling pool for this specific node
		hubManager.RegisterNode(nodeCopy, dialerFunc)

		// 6. Start the local SOCKS5 listener, strictly bound to localhost
		go startLocalSocksListener(nodeCopy, hubManager)
	}

	// Block the main thread to keep daemons running indefinitely
	select {}
}

// startLocalSocksListener boots up a TCP server listening exclusively on 127.0.0.1.
// It acts as the local bridge for X-UI's outbound routing.
func startLocalSocksListener(node config.ForeignNode, hubManager *pool.HubManager) {
	listenAddr := fmt.Sprintf("127.0.0.1:%d", node.LocalSocksPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		color.Red("[x] CRITICAL: Failed to bind SOCKS5 listener for [%s] on %s: %v", node.Alias, listenAddr, err)
		return
	}

	color.Green("[✓] SOCKS5 Ingress active for [%s] on %s", node.Alias, listenAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue // Silently ignore transient socket accept errors
		}

		go handleClientTraffic(clientConn, node.Alias, hubManager)
	}
}

// handleClientTraffic processes the local SOCKS5 handshake, extracts the target metadata,
// and multiplexes the payload over a Yamux stream.
func handleClientTraffic(localConn net.Conn, nodeAlias string, hubManager *pool.HubManager) {
	defer localConn.Close()

	// 1. Negotiate SOCKS5 and read the request (command + destination).
	cmd, dst, err := readSocksRequest(localConn)
	if err != nil {
		// Silently drop bad requests/scanners to conserve CPU and RAM
		return
	}

	switch cmd {
	case cmdConnect:
		// Reply success (BND 0.0.0.0:0) and pipe the TCP stream.
		if err := sendSocksReply(localConn, repSuccess, net.IPv4zero, 0); err != nil {
			return
		}
		_ = localConn.SetDeadline(time.Time{}) // drop the handshake deadline for the tunnel
		handleTCPConnect(localConn, dst, nodeAlias, hubManager)
	case cmdUDPAssociate:
		handleUDPAssociate(localConn, nodeAlias, hubManager)
	default:
		_ = sendSocksReply(localConn, repCmdNotSupported, net.IPv4zero, 0)
	}
}

// handleTCPConnect multiplexes a SOCKS5 CONNECT over a Yamux stream to the egress.
func handleTCPConnect(localConn net.Conn, targetDest, nodeAlias string, hubManager *pool.HubManager) {
	// Request a multiplexed logical stream from the TCP sub-pool.
	stream, err := hubManager.GetStreamTCP(nodeAlias)
	if err != nil {
		// Pool temporarily exhausted or dead: drop; X-UI/Xray core retries.
		return
	}
	defer stream.Close()

	// Announce the stream as a TCP CONNECT and inject the target address:
	// [StreamTCP][u16 len][target]
	if err := tunproto.WriteTCPHeader(stream, targetDest); err != nil {
		return
	}

	// Full-duplex pipe between the local X-UI connection and the Yamux stream.
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, localConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(localConn, stream)
		errChan <- err
	}()
	<-errChan
}
