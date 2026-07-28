package ingress

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

// feedSocks writes a full SOCKS5 greeting + request to the client side of a pipe
// and returns what the server wrote back (the method reply + any REP).
func TestReadSocksRequestConnect(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		// greeting: VER=5, NMETHODS=1, METHOD=0
		c.Write([]byte{0x05, 0x01, 0x00})
		// method reply (2 bytes) is read by us below
		buf := make([]byte, 2)
		c.Read(buf)
		// request: VER,CMD=CONNECT,RSV,ATYP=domain,len,"example.com",port 443
		req := []byte{0x05, cmdConnect, 0x00, addrTypeDomain, byte(len("example.com"))}
		req = append(req, []byte("example.com")...)
		req = append(req, 0x01, 0xBB) // 443
		c.Write(req)
	}()

	cmd, dst, err := readSocksRequest(s)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != cmdConnect {
		t.Fatalf("cmd = %#x", cmd)
	}
	if dst != "example.com:443" {
		t.Fatalf("dst = %q", dst)
	}
}

func TestReadSocksRequestUDPAssociateIPv4(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		c.Write([]byte{0x05, 0x01, 0x00})
		buf := make([]byte, 2)
		c.Read(buf)
		// UDP ASSOCIATE with IPv4 0.0.0.0:0 (typical client "don't know yet")
		c.Write([]byte{0x05, cmdUDPAssociate, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0})
	}()

	cmd, dst, err := readSocksRequest(s)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != cmdUDPAssociate {
		t.Fatalf("cmd = %#x", cmd)
	}
	if dst != "0.0.0.0:0" {
		t.Fatalf("dst = %q", dst)
	}
}

func TestSendSocksReply(t *testing.T) {
	var buf bytes.Buffer
	if err := sendSocksReply(&buf, repSuccess, net.IPv4(127, 0, 0, 1), 40000); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := []byte{0x05, 0x00, 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x9C, 0x40} // 40000 = 0x9C40
	if !bytes.Equal(got, want) {
		t.Fatalf("reply = %v, want %v", got, want)
	}
}

// TestRelayUDP drives the relay pump end-to-end with a fake tunnel stream.
func TestRelayUDP(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	streamHub, streamEgress := net.Pipe() // fake tunnel stream
	ctrlA, ctrlB := net.Pipe()            // fake SOCKS control conn
	defer ctrlA.Close()

	go relayUDP(ctrlB, relay, streamHub)

	// A UDP "client" (stands in for Xray) sends a datagram to the relay socket.
	client, err := net.DialUDP("udp", nil, relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// SOCKS UDP header: RSV,FRAG,ATYP=IPv4 8.8.8.8:53 + "ping"
	pkt := []byte{0x00, 0x00, 0x00, addrTypeIPv4, 8, 8, 8, 8, 0x00, 0x35}
	pkt = append(pkt, []byte("ping")...)
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// The egress side of the tunnel should receive a tunproto datagram for 8.8.8.8:53.
	streamEgress.SetReadDeadline(time.Now().Add(3 * time.Second))
	addr, payload, err := tunproto.ReadDatagram(streamEgress)
	if err != nil {
		t.Fatalf("read tunnel datagram: %v", err)
	}
	if addr.HostPort() != "8.8.8.8:53" || string(payload) != "ping" {
		t.Fatalf("got addr=%q payload=%q", addr.HostPort(), payload)
	}

	// Now the egress replies with a datagram; the client should get it as a SOCKS reply.
	if err := tunproto.WriteDatagram(streamEgress, tunproto.Addr{IP: net.ParseIP("8.8.8.8"), Port: 53}, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 512)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	// Expect SOCKS UDP header (10 bytes for IPv4) + "pong".
	if n < 10 || string(rbuf[10:n]) != "pong" {
		t.Fatalf("client got %d bytes: %v", n, rbuf[:n])
	}

	// Closing the control conn should tear the association down.
	ctrlA.Close()
}
