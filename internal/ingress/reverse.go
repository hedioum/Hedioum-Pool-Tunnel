package ingress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pool"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/proxyproto"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/securestream"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tlscert"
)

// reverseCertDir holds the hub's certificate cache for its reverse listeners (the same
// location the foreign egress uses; the unit's ReadWritePaths already covers it). A
// variable so tests can point it at a temp dir.
var reverseCertDir = "/etc/hedioum/tls"

// reverseNodes reports whether any configured node is a reverse-tunnel node.
func reverseNodes(nodes []config.ForeignNode) bool {
	for _, n := range nodes {
		if n.Reverse {
			return true
		}
	}
	return false
}

// startReverseListeners opens the camouflage listeners for every reverse node. In a
// reverse tunnel the foreign dials the hub, so the hub plays the SERVER side of the
// mimic handshake (authenticating the foreign with the node's token and routing
// unauthorized probes to the decoy), then still acts as the yamux CLIENT: it keeps
// opening every logical stream, so nothing downstream of the pool changes.
func startReverseListeners(cfg *config.AppConfig, hubManager *pool.HubManager) {
	if !reverseNodes(cfg.ForeignNodes) {
		return
	}

	filter := securestream.NewReplayFilter(0)

	// Certificates: one manager per distinct SNI, so the self-signed cert a probe or a
	// passive observer sees is issued for the same name the foreign sends as SNI. A
	// listener without an SNI uses the hub's default (cfg.Domain / localhost). A real
	// Let's Encrypt cert is only possible when the SNI is the hub's own domain.
	certMgrs := map[string]*tlscert.CertManager{}
	certFor := func(sni string) (*tlscert.CertManager, error) {
		if cm, ok := certMgrs[sni]; ok {
			return cm, nil
		}
		var cm *tlscert.CertManager
		var err error
		if sni == "" {
			cm, err = tlscert.NewCertManager(reverseCertDir, cfg.Domain, cfg.ACMEEmail, cfg.Domain)
		} else {
			sum := sha256.Sum256([]byte(sni))
			dir := filepath.Join(reverseCertDir, "rev-"+hex.EncodeToString(sum[:])[:10])
			domain := ""
			if sni == cfg.Domain {
				domain = cfg.Domain
			}
			cm, err = tlscert.NewCertManager(dir, domain, cfg.ACMEEmail, sni)
		}
		if err == nil {
			certMgrs[sni] = cm
		}
		return cm, err
	}

	for _, node := range cfg.ForeignNodes {
		if !node.Reverse {
			continue
		}
		style := reverseDecoyStyle(cfg, node)
		for _, ml := range node.ReverseListeners {
			certMgr, err := certFor(ml.ServerName)
			if err != nil {
				slog.Error("failed to initialize certificate for reverse listener", "node", node.Alias, "sni", ml.ServerName, "err", err)
				continue
			}
			m, err := egress.BuildServerMimic(node.AuthToken, style, ml, filter, certMgr)
			if err != nil {
				slog.Error("failed to build reverse mimic", "node", node.Alias, "type", ml.Type, "err", err)
				continue
			}
			go serveReverseListener(node, ml, m, hubManager)
		}
	}
}

// reverseDecoyStyle is the decoy persona a node's reverse listeners wear: the node's
// own setting (matching its foreign), else the hub's, else apache.
func reverseDecoyStyle(cfg *config.AppConfig, node config.ForeignNode) string {
	switch {
	case node.ReverseDecoyStyle != "":
		return node.ReverseDecoyStyle
	case cfg.DecoyStyle != "":
		return cfg.DecoyStyle
	}
	return "apache"
}

// proxyHeaderTimeout bounds how long a connection from the front proxy may take to
// send its PROXY header.
const proxyHeaderTimeout = 5 * time.Second

// reverseListenAddr is where a node's reverse listener binds.
func reverseListenAddr(node config.ForeignNode, port int) string {
	return net.JoinHostPort(node.ReverseBind, fmt.Sprint(port))
}

// serveReverseListener binds one port and adopts every authenticated foreign pipe.
func serveReverseListener(node config.ForeignNode, ml config.MimicListener, m mimic.ServerMimic, hubManager *pool.HubManager) {
	listenAddr := reverseListenAddr(node, ml.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("failed to bind reverse listener", "node", node.Alias, "type", ml.Type, "addr", listenAddr, "err", err)
		return
	}
	slog.Info("reverse listener active", "node", node.Alias, "type", ml.Type, "addr", listenAddr, "proxy_protocol", node.ReverseProxyProtocol)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(conn net.Conn) {
			if node.ReverseProxyProtocol {
				// Behind a front proxy: take the real client address from its PROXY
				// header. A connection that did not come through the proxy is dropped.
				c, err := proxyproto.Accept(conn, proxyHeaderTimeout)
				if err != nil {
					slog.Debug("reverse listener dropped a connection without a PROXY header", "node", node.Alias, "err", err)
					conn.Close()
					return
				}
				conn = c
			}
			handleReverseConn(conn, node.Alias, ml.Type, m, hubManager)
		}(conn)
	}
}

// handleReverseConn runs the server-side mimic handshake on a connection the foreign
// dialed, then hands the resulting yamux session to the node's pool.
func handleReverseConn(conn net.Conn, alias, mimicType string, m mimic.ServerMimic, hubManager *pool.HubManager) {
	secureConn, replayConn, err := m.Accept(conn)
	if err != nil {
		// Wrong credential, replayed handshake or a plain probe: serve the decoy so the
		// port looks like the real service it mimics (no ban, uniform behaviour).
		go m.ProxyDecoy(replayConn)
		return
	}

	// The hub opens every stream, so it is the yamux client even though it accepted
	// the TCP connection; the foreign runs the yamux server side.
	session, err := yamux.Client(secureConn, hubYamuxConfig())
	if err != nil {
		secureConn.Close()
		return
	}
	if err := hubManager.AdoptSession(alias, session, mimicType); err != nil {
		slog.Warn("reverse pipe rejected", "node", alias, "mimic", mimicType, "err", err)
		session.Close()
		return
	}
	slog.Info("reverse pipe established", "node", alias, "mimic", mimicType)
	go keepAlive(session)
}
