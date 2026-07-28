package tunproto

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestStreamTypeAndTCPHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPHeader(&buf, "youtube.com:443"); err != nil {
		t.Fatal(err)
	}
	typ, err := ReadStreamType(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != StreamTCP {
		t.Fatalf("type = %#x, want StreamTCP", typ)
	}
	target, err := ReadTCPTarget(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if target != "youtube.com:443" {
		t.Fatalf("target = %q", target)
	}
}

func TestTCPHeaderRejectsBadLength(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPHeader(&buf, ""); err == nil {
		t.Fatal("empty target should error")
	}
	if err := WriteTCPHeader(&buf, strings.Repeat("a", maxTargetLen+1)); err == nil {
		t.Fatal("oversize target should error")
	}
}

func TestUDPHeaderMarker(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteUDPHeader(&buf); err != nil {
		t.Fatal(err)
	}
	typ, err := ReadStreamType(&buf)
	if err != nil || typ != StreamUDP {
		t.Fatalf("type = %#x err = %v, want StreamUDP", typ, err)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr Addr
	}{
		{"ipv4", Addr{IP: net.ParseIP("8.8.8.8"), Port: 53}},
		{"ipv6", Addr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 443}},
		{"domain", Addr{Domain: "example.com", Port: 443}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := []byte("the quick brown fox")
			var buf bytes.Buffer
			if err := WriteDatagram(&buf, c.addr, payload); err != nil {
				t.Fatal(err)
			}
			gotAddr, gotPayload, err := ReadDatagram(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if gotAddr.HostPort() != c.addr.HostPort() {
				t.Fatalf("addr = %q, want %q", gotAddr.HostPort(), c.addr.HostPort())
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatalf("payload = %q", gotPayload)
			}
		})
	}
}

func TestDatagramMultipleInStream(t *testing.T) {
	var buf bytes.Buffer
	addrs := []Addr{
		{IP: net.ParseIP("1.1.1.1"), Port: 53},
		{Domain: "a.test", Port: 80},
		{IP: net.ParseIP("::1"), Port: 9000},
	}
	for i, a := range addrs {
		if err := WriteDatagram(&buf, a, []byte{byte(i), byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range addrs {
		got, payload, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got.HostPort() != addrs[i].HostPort() {
			t.Fatalf("record %d addr = %q, want %q", i, got.HostPort(), addrs[i].HostPort())
		}
		if len(payload) != 2 || payload[0] != byte(i) {
			t.Fatalf("record %d payload = %v", i, payload)
		}
	}
}

func TestSocksUDPHeaderParseAndBuild(t *testing.T) {
	// Build a SOCKS5 UDP request header + data by hand: RSV(0,0) FRAG(0) ATYP=1 IP PORT DATA
	pkt := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 4, 4, 0x00, 0x35}
	pkt = append(pkt, []byte("dnsquery")...)

	addr, off, err := ParseSocksUDPHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if addr.HostPort() != "8.8.4.4:53" {
		t.Fatalf("addr = %q", addr.HostPort())
	}
	if string(pkt[off:]) != "dnsquery" {
		t.Fatalf("data = %q", pkt[off:])
	}

	// Round-trip back to a SOCKS reply header.
	reply := BuildSocksUDPHeader(addr, []byte("dnsreply"))
	addr2, off2, err := ParseSocksUDPHeader(reply)
	if err != nil {
		t.Fatal(err)
	}
	if addr2.HostPort() != "8.8.4.4:53" || string(reply[off2:]) != "dnsreply" {
		t.Fatalf("reply round-trip failed: %q %q", addr2.HostPort(), reply[off2:])
	}
}

func TestSocksUDPHeaderRejectsFragment(t *testing.T) {
	pkt := []byte{0x00, 0x00, 0x02, 0x01, 8, 8, 4, 4, 0x00, 0x35} // FRAG=2
	if _, _, err := ParseSocksUDPHeader(pkt); err == nil {
		t.Fatal("fragmented datagram must be rejected")
	}
}

func TestDecodeAddrErrors(t *testing.T) {
	if _, _, err := decodeAddr([]byte{0x09, 1, 2, 3}); err != errBadAtyp {
		t.Fatalf("unknown ATYP: err = %v", err)
	}
	if _, _, err := decodeAddr([]byte{atypIPv4, 1, 2}); err != errShortAddr {
		t.Fatalf("truncated IPv4: err = %v", err)
	}
	if _, _, err := decodeAddr([]byte{atypDomain, 5, 'a', 'b'}); err != errShortAddr {
		t.Fatalf("truncated domain: err = %v", err)
	}
}
