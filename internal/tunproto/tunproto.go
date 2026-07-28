// Package tunproto defines the framing that rides inside each authenticated
// yamux stream between the Iran hub and the foreign egress. Keeping it in one
// place stops the ingress and egress sides from drifting.
//
// Every logical stream begins with a 1-byte stream type:
//
//	0x01 StreamTCP  -> [0x01][u16 targetLen][target "host:port"] , then raw bytes
//	0x03 StreamUDP  -> [0x03] , then a sequence of length-prefixed datagrams:
//	                   [u16 recordLen][ATYP][ADDR][PORT][payload]
//
// The ATYP/ADDR/PORT encoding is identical to SOCKS5's address encoding, so the
// hub can move bytes between the SOCKS UDP header and a datagram record with no
// reformatting. This package is deliberately OS-independent so the ingress side
// can later be reused in a cross-platform client package.
package tunproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Stream types (first byte of every logical stream).
const (
	StreamTCP byte = 0x01
	StreamUDP byte = 0x03
)

// SOCKS-style address types.
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04
)

const (
	// maxTargetLen bounds the TCP target string.
	maxTargetLen = 2048
	// maxRecord is the largest UDP datagram record (u16 length prefix).
	maxRecord = 0xFFFF
)

var (
	errTargetLen  = errors.New("tunproto: target length out of range")
	errRecordLen  = errors.New("tunproto: datagram record too large")
	errShortAddr  = errors.New("tunproto: truncated address")
	errBadAtyp    = errors.New("tunproto: unknown address type")
	errEmptyChunk = errors.New("tunproto: empty datagram record")
)

// ReadStreamType reads the leading stream-type byte.
func ReadStreamType(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// --- TCP header ---

// WriteTCPHeader writes [StreamTCP][u16 len][target].
func WriteTCPHeader(w io.Writer, target string) error {
	if len(target) == 0 || len(target) > maxTargetLen {
		return errTargetLen
	}
	buf := make([]byte, 1+2+len(target))
	buf[0] = StreamTCP
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(target)))
	copy(buf[3:], target)
	_, err := w.Write(buf)
	return err
}

// ReadTCPTarget reads [u16 len][target] (the stream type byte must already be
// consumed via ReadStreamType).
func ReadTCPTarget(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > maxTargetLen {
		return "", errTargetLen
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// --- UDP header + datagrams ---

// WriteUDPHeader writes the [StreamUDP] marker that opens a UDP stream.
func WriteUDPHeader(w io.Writer) error {
	_, err := w.Write([]byte{StreamUDP})
	return err
}

// Addr is a SOCKS-style destination used in UDP datagram records. Exactly one of
// IP or Domain is set.
type Addr struct {
	IP     net.IP
	Domain string
	Port   uint16
}

// HostPort renders the address for dialing (net.JoinHostPort form).
func (a Addr) HostPort() string {
	host := a.Domain
	if host == "" && a.IP != nil {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
}

// encodedLen returns the number of bytes Addr.encode will write.
func (a Addr) encodedLen() int {
	if a.Domain != "" {
		return 1 + 1 + len(a.Domain) + 2 // ATYP + dlen + domain + port
	}
	if ip4 := a.IP.To4(); ip4 != nil {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

// encode writes ATYP+ADDR+PORT into dst (which must be >= encodedLen) and
// returns the number of bytes written.
func (a Addr) encode(dst []byte) int {
	n := 0
	switch {
	case a.Domain != "":
		dst[0] = atypDomain
		dst[1] = byte(len(a.Domain))
		n = 2 + copy(dst[2:], a.Domain)
	case a.IP.To4() != nil:
		dst[0] = atypIPv4
		n = 1 + copy(dst[1:], a.IP.To4())
	default:
		dst[0] = atypIPv6
		n = 1 + copy(dst[1:], a.IP.To16())
	}
	binary.BigEndian.PutUint16(dst[n:], a.Port)
	return n + 2
}

// decodeAddr parses a SOCKS-style address from the front of b, returning the
// address and the number of bytes it consumed.
func decodeAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, errShortAddr
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return Addr{}, 0, errShortAddr
		}
		ip := make(net.IP, 4)
		copy(ip, b[1:5])
		return Addr{IP: ip, Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case atypIPv6:
		if len(b) < 1+16+2 {
			return Addr{}, 0, errShortAddr
		}
		ip := make(net.IP, 16)
		copy(ip, b[1:17])
		return Addr{IP: ip, Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case atypDomain:
		if len(b) < 2 {
			return Addr{}, 0, errShortAddr
		}
		dlen := int(b[1])
		end := 2 + dlen + 2
		if len(b) < end {
			return Addr{}, 0, errShortAddr
		}
		domain := string(b[2 : 2+dlen])
		return Addr{Domain: domain, Port: binary.BigEndian.Uint16(b[2+dlen : end])}, end, nil
	default:
		return Addr{}, 0, errBadAtyp
	}
}

// WriteDatagram frames one datagram as [u16 recordLen][ATYP][ADDR][PORT][payload]
// and writes it in a single Write. Callers with concurrent writers to the same
// stream must serialize their WriteDatagram calls externally.
func WriteDatagram(w io.Writer, addr Addr, payload []byte) error {
	recordLen := addr.encodedLen() + len(payload)
	if recordLen == 0 {
		return errEmptyChunk
	}
	if recordLen > maxRecord {
		return errRecordLen
	}
	buf := make([]byte, 2+recordLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(recordLen))
	n := addr.encode(buf[2:])
	copy(buf[2+n:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram reads one framed datagram, returning its destination/source
// address and an owned copy of the payload.
func ReadDatagram(r io.Reader) (Addr, []byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Addr{}, nil, err
	}
	recordLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if recordLen == 0 {
		return Addr{}, nil, errEmptyChunk
	}
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(r, record); err != nil {
		return Addr{}, nil, err
	}
	addr, n, err := decodeAddr(record)
	if err != nil {
		return Addr{}, nil, err
	}
	payload := make([]byte, recordLen-n)
	copy(payload, record[n:])
	return addr, payload, nil
}

// AddrFromUDP builds an Addr from a resolved UDP address (used for egress->hub
// response datagrams).
func AddrFromUDP(u *net.UDPAddr) Addr {
	return Addr{IP: u.IP, Port: uint16(u.Port)}
}

// ParseSocksUDPHeader parses a SOCKS5 UDP request header
// ([RSV(2)][FRAG(1)][ATYP][ADDR][PORT]) and returns the destination address and
// the offset where the DATA payload begins. FRAG != 0 is rejected.
func ParseSocksUDPHeader(b []byte) (Addr, int, error) {
	if len(b) < 3 {
		return Addr{}, 0, errShortAddr
	}
	if b[2] != 0 {
		return Addr{}, 0, fmt.Errorf("tunproto: fragmented UDP not supported (FRAG=%d)", b[2])
	}
	addr, n, err := decodeAddr(b[3:])
	if err != nil {
		return Addr{}, 0, err
	}
	return addr, 3 + n, nil
}

// BuildSocksUDPHeader writes a SOCKS5 UDP reply header for addr into a new slice
// and appends payload, ready to send to the local SOCKS client.
func BuildSocksUDPHeader(addr Addr, payload []byte) []byte {
	out := make([]byte, 3+addr.encodedLen()+len(payload))
	// RSV(2)=0, FRAG(1)=0 already zero.
	n := addr.encode(out[3:])
	copy(out[3+n:], payload)
	return out
}
