package egress

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeSocks is a minimal no-auth SOCKS5 server: CONNECT answers with an echo of the
// stream, UDP ASSOCIATE relays datagrams back unchanged. It records the destination it
// was asked for.
type fakeSocks struct {
	ln   net.Listener
	dest chan string
}

func startFakeSocks(t *testing.T) *fakeSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks{ln: ln, dest: make(chan string, 4)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(t, c)
		}
	}()
	return f
}

func readSocksAddr(c net.Conn) (string, error) {
	var a [1]byte
	if _, err := io.ReadFull(c, a[:]); err != nil {
		return "", err
	}
	var host string
	switch a[0] {
	case socksAtypIPv4:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case socksAtypIPv6:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case socksAtypName:
		var l [1]byte
		io.ReadFull(c, l[:])
		b := make([]byte, l[0])
		io.ReadFull(c, b)
		host = string(b)
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func (f *fakeSocks) serve(t *testing.T, c net.Conn) {
	defer c.Close()
	var g [3]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	var h [4]byte
	if _, err := io.ReadFull(c, h[:2+2]); err != nil {
		return
	}
	// h = VER CMD RSV ATYP; the address follows, ATYP already consumed into h[3]
	cmd := h[1]
	// put ATYP back by wrapping the conn
	addr, err := readSocksAddr(&prefixConn{Conn: c, pre: []byte{h[3]}})
	if err != nil {
		return
	}
	switch cmd {
	case socksCmdConn:
		f.dest <- addr
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		io.Copy(c, c)
	case socksCmdUDP:
		u, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer u.Close()
		port := u.LocalAddr().(*net.UDPAddr).Port
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := u.ReadFrom(buf)
				if err != nil {
					return
				}
				// header: 0 0 0 ATYP ADDR PORT -> report the destination, echo the data back
				r := &prefixConn{Conn: nil, pre: buf[3:n]}
				d, _ := readSocksAddr(r)
				f.dest <- d
				u.WriteTo(buf[:n], from)
			}
		}()
		io.Copy(io.Discard, c) // association lives while the control connection does
	}
}

// prefixConn feeds already-read bytes before the real connection.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	if p.Conn == nil {
		return 0, io.EOF
	}
	return p.Conn.Read(b)
}

func withUpstream(t *testing.T, addr string) {
	t.Helper()
	old := egressUpstream
	egressUpstream = addr
	t.Cleanup(func() { egressUpstream = old })
}

func TestUpstreamTCPGoesThroughProxy(t *testing.T) {
	f := startFakeSocks(t)
	withUpstream(t, f.ln.Addr().String())
	c, err := safeDialTarget("93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-f.dest; got != "93.184.216.34:443" {
		t.Fatalf("proxy asked for %q", got)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("stream through the proxy broken: %q %v", buf, err)
	}
}

func TestUpstreamUDPGoesThroughProxy(t *testing.T) {
	f := startFakeSocks(t)
	withUpstream(t, f.ln.Addr().String())
	c, err := safeDialUDP("93.184.216.34:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := <-f.dest; got != "93.184.216.34:53" {
		t.Fatalf("proxy was told %q", got)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("UDP reply must come back without the SOCKS header: %q %v", buf[:n], err)
	}
}

// An upstream is not a way around the SSRF gate, and a dead upstream must never fall
// back to a direct connection.
func TestUpstreamKeepsSSRFGateAndFailsClosed(t *testing.T) {
	f := startFakeSocks(t)
	withUpstream(t, f.ln.Addr().String())
	if _, err := safeDialTarget("169.254.169.254:80"); !errors.Is(err, errBlockedTarget) {
		t.Fatalf("a private target must be blocked, got %v", err)
	}
	if _, err := safeDialUDP("10.0.0.1:53"); !errors.Is(err, errBlockedTarget) {
		t.Fatalf("a private UDP target must be blocked, got %v", err)
	}
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	withUpstream(t, addr)
	if c, err := safeDialTarget("93.184.216.34:443"); err == nil {
		c.Close()
		t.Fatal("a dead upstream must fail, not dial directly")
	}
}
