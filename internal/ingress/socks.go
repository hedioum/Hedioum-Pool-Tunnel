package ingress

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socksVersion5   = 0x05
	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03
	addrTypeIPv4    = 0x01
	addrTypeDomain  = 0x03
	addrTypeIPv6    = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repCmdNotSupported = 0x07

	handshakeTimeout = 3 * time.Second
)

// readSocksRequest performs the SOCKS5 greeting/no-auth negotiation and reads the
// client request line. It returns the command and destination "host:port" but
// does NOT send the final reply, which differs between CONNECT and UDP ASSOCIATE.
// A deadline is applied for the negotiation; the caller manages it afterwards.
func readSocksRequest(conn net.Conn) (cmd byte, dst string, err error) {
	if err = conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return 0, "", err
	}

	// Greeting: VER, NMETHODS, METHODS.
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		return 0, "", errors.New("failed to read SOCKS5 greeting")
	}
	if greeting[0] != socksVersion5 {
		return 0, "", errors.New("invalid SOCKS version")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err = io.ReadFull(conn, methods); err != nil {
		return 0, "", errors.New("failed to read SOCKS5 auth methods")
	}
	// Reply: No-Authentication (0x00).
	if _, err = conn.Write([]byte{socksVersion5, 0x00}); err != nil {
		return 0, "", errors.New("failed to write SOCKS5 auth response")
	}

	// Request header: VER, CMD, RSV, ATYP.
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return 0, "", errors.New("failed to read SOCKS5 request header")
	}
	if header[0] != socksVersion5 {
		return 0, "", errors.New("invalid SOCKS version in request")
	}
	cmd = header[1]

	destAddr, err := readSocksAddr(conn, header[3])
	if err != nil {
		return 0, "", err
	}
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return 0, "", errors.New("failed to read destination port")
	}
	dst = net.JoinHostPort(destAddr, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf))))
	return cmd, dst, nil
}

// readSocksAddr parses the ATYP-specific address field.
func readSocksAddr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case addrTypeIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", errors.New("failed to read IPv4 address")
		}
		return net.IP(ip).String(), nil
	case addrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", errors.New("failed to read domain length")
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", errors.New("failed to read domain name")
		}
		return string(domain), nil
	case addrTypeIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", errors.New("failed to read IPv6 address")
		}
		return net.IP(ip).String(), nil
	default:
		return "", errors.New("unsupported address type")
	}
}

// sendSocksReply writes a SOCKS5 reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
func sendSocksReply(w io.Writer, rep byte, bindIP net.IP, bindPort uint16) error {
	reply := []byte{socksVersion5, rep, 0x00}
	if ip4 := bindIP.To4(); ip4 != nil {
		reply = append(reply, addrTypeIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, addrTypeIPv6)
		reply = append(reply, bindIP.To16()...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], bindPort)
	reply = append(reply, portBuf[:]...)

	_, err := w.Write(reply)
	return err
}
