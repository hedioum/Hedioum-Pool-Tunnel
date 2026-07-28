package egress

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

const (
	udpIdleTimeout = 60 * time.Second // close a UDP flow after this much silence
	udpMaxFlows    = 256              // per-stream NAT table cap (FD/memory guard)
	udpReadBufSize = 64 * 1024
)

// dialUDP is the seam used to open a vetted UDP socket to a target; overridable
// in tests to reach a loopback echo server without tripping the SSRF gate.
var dialUDP = safeDialUDP

// udpFlow is one connected UDP socket to a single target, with an idle timer.
type udpFlow struct {
	conn   *net.UDPConn
	target tunproto.Addr // echoed back as the source of responses
	timer  *time.Timer
}

// handleUDPStream relays a UDP association's datagrams to the internet. It keeps a
// per-stream NAT table of connected UDP sockets (one per target) with idle
// timeouts, bounds the table size, and applies the same SSRF gate as TCP to every
// target. Responses are written back on the stream as tunproto datagrams.
func handleUDPStream(stream net.Conn) {
	var mu sync.Mutex
	flows := make(map[string]*udpFlow)
	var streamWriteMu sync.Mutex // multiple flow readers write back to one stream

	closeFlow := func(key string) {
		mu.Lock()
		if f, ok := flows[key]; ok {
			delete(flows, key)
			f.timer.Stop()
			f.conn.Close()
		}
		mu.Unlock()
	}

	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.timer.Stop()
			f.conn.Close()
		}
		mu.Unlock()
	}()

	for {
		addr, payload, err := tunproto.ReadDatagram(stream)
		if err != nil {
			return
		}
		key := addr.HostPort()

		mu.Lock()
		f, ok := flows[key]
		if !ok {
			if len(flows) >= udpMaxFlows {
				mu.Unlock()
				continue // table full: drop
			}
			uconn, derr := dialUDP(key)
			if derr != nil {
				mu.Unlock()
				if errors.Is(derr, errBlockedTarget) {
					color.Red("[!] Blocked UDP SSRF attempt to %s", key)
				}
				continue
			}
			f = &udpFlow{conn: uconn, target: addr}
			f.timer = time.AfterFunc(udpIdleTimeout, func() { closeFlow(key) })
			flows[key] = f
			go udpResponseReader(f, key, stream, &streamWriteMu, closeFlow)
		}
		mu.Unlock()

		f.timer.Reset(udpIdleTimeout)
		if _, werr := f.conn.Write(payload); werr != nil {
			closeFlow(key)
		}
	}
}

// udpResponseReader reads datagrams coming back from the target and writes them to
// the tunnel stream (source = the target address), until the socket closes.
func udpResponseReader(f *udpFlow, key string, stream net.Conn, streamWriteMu *sync.Mutex, closeFlow func(string)) {
	defer closeFlow(key)
	buf := make([]byte, udpReadBufSize)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			return
		}
		f.timer.Reset(udpIdleTimeout)
		streamWriteMu.Lock()
		werr := tunproto.WriteDatagram(stream, f.target, buf[:n])
		streamWriteMu.Unlock()
		if werr != nil {
			return
		}
	}
}
