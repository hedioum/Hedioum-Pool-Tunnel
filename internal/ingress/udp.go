package ingress

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pool"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

const (
	udpBufSize    = 64 * 1024 // max datagram we read from the local SOCKS client
	udpQueueDepth = 256       // bounded outbound queue; drop when full (UDP tolerates loss)
)

// handleUDPAssociate implements SOCKS5 UDP ASSOCIATE. It opens a localhost relay
// UDP socket, tells the client where to send its datagrams, opens ONE UDP tunnel
// stream to the egress, and relays datagrams both ways until the control TCP
// connection closes (RFC 1928: the association lives with its control conn).
//
// Backpressure policy: the client->tunnel path uses a bounded queue and drops
// datagrams when the tunnel is congested, so a slow link never stalls the read
// loop or grows memory unboundedly.
func handleUDPAssociate(ctrlConn net.Conn, nodeAlias string, hubManager *pool.HubManager) {
	// 1. Relay UDP socket on loopback (same host as Xray; same model in a future
	// client package).
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = sendSocksReply(ctrlConn, repGeneralFailure, net.IPv4zero, 0)
		return
	}
	defer relay.Close()

	localPort := uint16(relay.LocalAddr().(*net.UDPAddr).Port)
	if err := sendSocksReply(ctrlConn, repSuccess, net.IPv4(127, 0, 0, 1), localPort); err != nil {
		return
	}
	_ = ctrlConn.SetDeadline(time.Time{}) // control conn now stays open for the association's lifetime

	// 2. Open a UDP tunnel stream on the dedicated UDP sub-pool.
	stream, err := hubManager.GetStreamUDP(nodeAlias)
	if err != nil {
		return
	}
	defer stream.Close()
	if err := tunproto.WriteUDPHeader(stream); err != nil {
		return
	}

	// 3. Relay datagrams both ways until teardown.
	relayUDP(ctrlConn, relay, stream)
}

// relayUDP pumps datagrams between the local relay UDP socket and the UDP tunnel
// stream, tearing down when the control conn or the stream closes. Extracted for
// testability (the tunnel stream can be any net.Conn).
func relayUDP(ctrlConn net.Conn, relay *net.UDPConn, stream net.Conn) {
	var clientAddr atomic.Pointer[net.UDPAddr] // learned from the first datagram
	done := make(chan struct{})
	var once sync.Once
	closeAll := func() { once.Do(func() { close(done) }) }

	type dgram struct {
		addr tunproto.Addr
		data []byte
	}
	sendCh := make(chan dgram, udpQueueDepth)

	// Writer: drains the queue to the tunnel stream (single writer -> no stream mutex).
	go func() {
		defer closeAll()
		for {
			select {
			case <-done:
				return
			case d := <-sendCh:
				if err := tunproto.WriteDatagram(stream, d.addr, d.data); err != nil {
					return
				}
			}
		}
	}()

	// A. Client -> tunnel (drop-on-congestion).
	go func() {
		defer closeAll()
		buf := make([]byte, udpBufSize)
		for {
			n, src, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr.Store(src)
			addr, off, err := tunproto.ParseSocksUDPHeader(buf[:n])
			if err != nil {
				continue // malformed or fragmented -> drop
			}
			data := make([]byte, n-off)
			copy(data, buf[off:n])
			select {
			case sendCh <- dgram{addr: addr, data: data}:
			default:
				// tunnel backed up -> drop this datagram
			}
		}
	}()

	// B. Tunnel -> client.
	go func() {
		defer closeAll()
		for {
			addr, payload, err := tunproto.ReadDatagram(stream)
			if err != nil {
				return
			}
			ca := clientAddr.Load()
			if ca == nil {
				continue // haven't seen the client's source address yet
			}
			if _, err := relay.WriteToUDP(tunproto.BuildSocksUDPHeader(addr, payload), ca); err != nil {
				return
			}
		}
	}()

	// C. Control watchdog: the association ends when the control TCP conn closes.
	go func() {
		defer closeAll()
		_, _ = io.Copy(io.Discard, ctrlConn)
	}()

	<-done
}
