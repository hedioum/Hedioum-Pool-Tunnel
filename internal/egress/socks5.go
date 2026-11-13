package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 client (RFC 1928, no authentication) used when egress_upstream is set: the
// foreign hands every outgoing TCP stream and UDP flow to a local SOCKS5 proxy (for
// example the mixed/socks inbound of 3x-ui or xray) instead of dialing the destination
// itself. The proxy then decides what is direct, what goes through WARP, and which IP
// family is used. There is no fallback: if the proxy is down the connection fails, so
// traffic meant for a proxy never leaves with the server's own address.

const (
	socksVer      = 0x05
	socksCmdConn  = 0x01
	socksCmdUDP   = 0x03
	socksAtypIPv4 = 0x01
	socksAtypName = 0x03
	socksAtypIPv6 = 0x04
)

// egressUpstream is the "host:port" of the SOCKS5 proxy, "" = direct. Set once at start.
var egressUpstream string

func socksAddr(host string, port int) ([]byte, error) {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append([]byte{socksAtypIPv4}, ip4...)
		} else {
			b = append([]byte{socksAtypIPv6}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid host %q", host)
		}
		b = append([]byte{socksAtypName, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// socksHandshake dials the proxy, negotiates "no auth" and sends one request. It returns
// the control connection and the address the proxy reported (BND.ADDR:BND.PORT).
func socksHandshake(proxy string, cmd byte, host string, port int) (net.Conn, string, int, error) {
	c, err := net.DialTimeout("tcp", proxy, dialTimeout)
	if err != nil {
		return nil, "", 0, fmt.Errorf("upstream proxy: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	fail := func(err error) (net.Conn, string, int, error) {
		c.Close()
		return nil, "", 0, err
	}
	if _, err := c.Write([]byte{socksVer, 1, 0x00}); err != nil {
		return fail(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return fail(fmt.Errorf("upstream proxy greeting: %w", err))
	}
	if sel[0] != socksVer || sel[1] != 0x00 {
		return fail(errors.New("upstream proxy requires authentication or is not SOCKS5"))
	}
	addr, err := socksAddr(host, port)
	if err != nil {
		return fail(err)
	}
	if _, err := c.Write(append([]byte{socksVer, cmd, 0x00}, addr...)); err != nil {
		return fail(err)
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return fail(fmt.Errorf("upstream proxy reply: %w", err))
	}
	if h[0] != socksVer {
		return fail(errors.New("upstream proxy sent a bad reply"))
	}
	if h[1] != 0x00 {
		return fail(fmt.Errorf("upstream proxy refused (code %d)", h[1]))
	}
	var bnd string
	switch h[3] {
	case socksAtypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return fail(err)
		}
		bnd = net.IP(a[:]).String()
	case socksAtypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return fail(err)
		}
		bnd = net.IP(a[:]).String()
	case socksAtypName:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		nb := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, nb); err != nil {
			return fail(err)
		}
		bnd = string(nb)
	default:
		return fail(errors.New("upstream proxy sent an unknown address type"))
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, bnd, int(binary.BigEndian.Uint16(pb[:])), nil
}

// socksDialTCP opens a TCP stream to host:port through the SOCKS5 proxy.
func socksDialTCP(proxy, host, port string) (net.Conn, error) {
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}
	c, _, _, err := socksHandshake(proxy, socksCmdConn, host, p)
	return c, err
}

// socksUDPConn is a UDP flow to one target relayed by the proxy (UDP ASSOCIATE). It
// satisfies net.Conn: Write adds the SOCKS5 UDP header, Read strips it, and closing it
// also closes the TCP control connection that keeps the association alive.
type socksUDPConn struct {
	net.Conn          // the UDP socket to the proxy's relay
	ctl      net.Conn // TCP control connection
	hdr      []byte   // RSV RSV FRAG ATYP ADDR PORT for the target
	rbuf     [65535 + 300]byte
}

func socksDialUDP(proxy, host, port string) (net.Conn, error) {
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}
	addr, err := socksAddr(host, p)
	if err != nil {
		return nil, err
	}
	// DST.ADDR/PORT of the request is what we will send from; 0.0.0.0:0 = unknown.
	ctl, bnd, bport, err := socksHandshake(proxy, socksCmdUDP, "0.0.0.0", 0)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(bnd); ip == nil || ip.IsUnspecified() {
		// The proxy did not say where its relay is: it is on the proxy's own host.
		bnd, _, _ = net.SplitHostPort(proxy)
	}
	u, err := net.DialTimeout("udp", net.JoinHostPort(bnd, strconv.Itoa(bport)), dialTimeout)
	if err != nil {
		ctl.Close()
		return nil, fmt.Errorf("upstream proxy UDP relay: %w", err)
	}
	sc := &socksUDPConn{Conn: u, ctl: ctl, hdr: append([]byte{0, 0, 0}, addr...)}
	// The association ends when the control connection closes; watch for that.
	go func() {
		_, _ = io.Copy(io.Discard, ctl)
		u.Close()
	}()
	return sc, nil
}

func (c *socksUDPConn) Write(p []byte) (int, error) {
	if _, err := c.Conn.Write(append(append(make([]byte, 0, len(c.hdr)+len(p)), c.hdr...), p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socksUDPConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(c.rbuf[:])
		if err != nil {
			return 0, err
		}
		b := c.rbuf[:n]
		if len(b) < 4 || b[2] != 0 { // malformed or fragmented: drop
			continue
		}
		off := 4
		switch b[3] {
		case socksAtypIPv4:
			off += 4
		case socksAtypIPv6:
			off += 16
		case socksAtypName:
			if len(b) < 5 {
				continue
			}
			off += 1 + int(b[4])
		default:
			continue
		}
		off += 2
		if len(b) < off {
			continue
		}
		return copy(p, b[off:]), nil
	}
}

func (c *socksUDPConn) Close() error {
	c.ctl.Close()
	return c.Conn.Close()
}
