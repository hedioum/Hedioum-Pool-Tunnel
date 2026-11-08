package ingress

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pool"
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

	// One certificate manager for all reverse listeners: self-signed by default, or a
	// real Let's Encrypt cert when cfg.Domain points at this hub.
	certMgr, err := tlscert.NewCertManager(reverseCertDir, cfg.Domain, cfg.ACMEEmail, cfg.Domain)
	if err != nil {
		slog.Error("failed to initialize certificate manager for reverse listeners", "err", err)
		return
	}
	filter := securestream.NewReplayFilter(0)

	style := cfg.DecoyStyle
	if style == "" {
		style = "apache"
	}

	for _, node := range cfg.ForeignNodes {
		if !node.Reverse {
			continue
		}
		for _, ml := range node.ReverseListeners {
			m, err := egress.BuildServerMimic(node.AuthToken, style, ml, filter, certMgr)
			if err != nil {
				slog.Error("failed to build reverse mimic", "node", node.Alias, "type", ml.Type, "err", err)
				continue
			}
			go serveReverseListener(node.Alias, ml, m, hubManager)
		}
	}
}

// serveReverseListener binds one port and adopts every authenticated foreign pipe.
func serveReverseListener(alias string, ml config.MimicListener, m mimic.ServerMimic, hubManager *pool.HubManager) {
	listenAddr := fmt.Sprintf(":%d", ml.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("failed to bind reverse listener", "node", alias, "type", ml.Type, "addr", listenAddr, "err", err)
		return
	}
	slog.Info("reverse listener active", "node", alias, "type", ml.Type, "addr", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleReverseConn(conn, alias, ml.Type, m, hubManager)
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
