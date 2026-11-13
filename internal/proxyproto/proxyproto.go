// Package proxyproto reads the PROXY protocol header (v1 text and v2 binary) that a
// front proxy such as nginx (`proxy_protocol on`) or HAProxy (`send-proxy`) prepends to
// a forwarded TCP connection, so the real client address survives the hop.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var v2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	v1Prefix    = "PROXY "
	v1MaxLen    = 107 // longest legal v1 line, CRLF included
	v2MaxHeader = 536 // fixed header + the largest address block we accept
)

// ErrNoHeader is returned when the connection does not start with a PROXY header.
var ErrNoHeader = errors.New("proxyproto: connection does not start with a PROXY header")

// conn serves the bytes after the header and reports the address the header carried.
type conn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *conn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *conn) RemoteAddr() net.Addr       { return c.remote }

// Accept consumes the PROXY header at the start of c (within timeout) and returns a
// connection whose RemoteAddr is the original client. A connection that does not start
// with a valid header is rejected: when a hub listener is configured to sit behind a
// proxy, anything that did not come through the proxy is not trusted.
func Accept(c net.Conn, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		defer c.SetReadDeadline(time.Time{})
	}
	br := bufio.NewReaderSize(c, 4096)
	head, err := br.Peek(12)
	if err != nil {
		return nil, fmt.Errorf("proxyproto: %w", err)
	}

	var remote net.Addr
	switch {
	case bytes.Equal(head, v2Sig):
		remote, err = readV2(br)
	case strings.HasPrefix(string(head), v1Prefix[:6]):
		remote, err = readV1(br)
	default:
		return nil, ErrNoHeader
	}
	if err != nil {
		return nil, err
	}
	if remote == nil {
		remote = c.RemoteAddr() // LOCAL / UNKNOWN: the proxy itself, keep the socket peer
	}
	return &conn{Conn: c, r: br, remote: remote}, nil
}

func readV1(br *bufio.Reader) (net.Addr, error) {
	var line []byte
	for len(line) < v1MaxLen {
		b, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("proxyproto: %w", err)
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	s := string(line)
	if !strings.HasSuffix(s, "\r\n") {
		return nil, errors.New("proxyproto: malformed v1 header")
	}
	f := strings.Fields(strings.TrimSuffix(s, "\r\n"))
	if len(f) < 2 || f[0] != "PROXY" {
		return nil, errors.New("proxyproto: malformed v1 header")
	}
	if f[1] == "UNKNOWN" {
		return nil, nil
	}
	if (f[1] != "TCP4" && f[1] != "TCP6") || len(f) != 6 {
		return nil, errors.New("proxyproto: malformed v1 header")
	}
	ip := net.ParseIP(f[2])
	port, perr := strconv.Atoi(f[4])
	if ip == nil || perr != nil || port < 0 || port > 65535 {
		return nil, errors.New("proxyproto: malformed v1 address")
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func readV2(br *bufio.Reader) (net.Addr, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("proxyproto: %w", err)
	}
	if hdr[12]>>4 != 2 {
		return nil, errors.New("proxyproto: unsupported version")
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > v2MaxHeader {
		return nil, errors.New("proxyproto: header too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("proxyproto: %w", err)
	}
	if hdr[12]&0x0f == 0 { // LOCAL: health check from the proxy itself
		return nil, nil
	}
	if hdr[12]&0x0f != 1 {
		return nil, errors.New("proxyproto: unknown command")
	}
	switch hdr[13] {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return nil, errors.New("proxyproto: short IPv4 block")
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}, nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return nil, errors.New("proxyproto: short IPv6 block")
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}, nil
	}
	return nil, nil // UDP / unix / unspecified: keep the socket peer
}
