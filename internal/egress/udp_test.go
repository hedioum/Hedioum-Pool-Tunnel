package egress

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

// TestHandleUDPStreamRelay checks the egress relays a datagram to a target and
// returns the response, using a loopback echo server via the dialUDP seam.
func TestHandleUDPStreamRelay(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], src)
		}
	}()

	orig := dialUDP
	dialUDP = func(string) (*net.UDPConn, error) {
		return net.DialUDP("udp", nil, echo.LocalAddr().(*net.UDPAddr))
	}
	defer func() { dialUDP = orig }()

	streamHub, streamEgress := net.Pipe()
	defer streamHub.Close()
	go handleUDPStream(streamEgress)

	target := tunproto.Addr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	if err := tunproto.WriteDatagram(streamHub, target, []byte("hello-udp")); err != nil {
		t.Fatal(err)
	}

	streamHub.SetReadDeadline(time.Now().Add(3 * time.Second))
	addr, payload, err := tunproto.ReadDatagram(streamHub)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if addr.HostPort() != "8.8.8.8:53" {
		t.Fatalf("response source = %q, want 8.8.8.8:53", addr.HostPort())
	}
	if string(payload) != "hello-udp" {
		t.Fatalf("response payload = %q", payload)
	}
}

// TestSafeDialUDPBlocksSSRF ensures UDP targets get the same SSRF gate as TCP.
func TestSafeDialUDPBlocksSSRF(t *testing.T) {
	for _, target := range []string{
		"127.0.0.1:53",
		"169.254.169.254:53", // cloud metadata over UDP
		"10.0.0.1:53",
		"192.168.1.1:53",
		"[::1]:53",
	} {
		if _, err := safeDialUDP(target); !errors.Is(err, errBlockedTarget) {
			t.Errorf("safeDialUDP(%q) err = %v, want errBlockedTarget", target, err)
		}
	}
}
