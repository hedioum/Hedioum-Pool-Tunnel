package egress

import (
	"net"
	"testing"
)

func TestPickFamily(t *testing.T) {
	v4 := net.ParseIP("8.8.8.8")
	v6 := net.ParseIP("2001:4860:4860::8888")

	orig := egressMode
	defer func() { egressMode = orig }()

	// ipv4 mode: prefer/require IPv4 even if IPv6 appears first.
	egressMode = egressIPv4
	if ip, isV4, err := pickFamily([]net.IP{v6, v4}, "h"); err != nil || !isV4 || !ip.Equal(v4) {
		t.Fatalf("ipv4 mode: ip=%v isV4=%v err=%v", ip, isV4, err)
	}
	if _, _, err := pickFamily([]net.IP{v6}, "h"); err == nil {
		t.Fatal("ipv4 mode with only IPv6 should error")
	}

	// ipv6 mode: require IPv6.
	egressMode = egressIPv6
	if ip, isV4, err := pickFamily([]net.IP{v4, v6}, "h"); err != nil || isV4 || !ip.Equal(v6) {
		t.Fatalf("ipv6 mode: ip=%v isV4=%v err=%v", ip, isV4, err)
	}
	if _, _, err := pickFamily([]net.IP{v4}, "h"); err == nil {
		t.Fatal("ipv6 mode with only IPv4 should error")
	}

	// dual mode: prefer IPv4, fall back to IPv6.
	egressMode = egressDual
	if ip, isV4, err := pickFamily([]net.IP{v6, v4}, "h"); err != nil || !isV4 || !ip.Equal(v4) {
		t.Fatalf("dual mode prefer v4: ip=%v isV4=%v err=%v", ip, isV4, err)
	}
	if ip, isV4, err := pickFamily([]net.IP{v6}, "h"); err != nil || isV4 || !ip.Equal(v6) {
		t.Fatalf("dual mode fallback v6: ip=%v isV4=%v err=%v", ip, isV4, err)
	}
}
