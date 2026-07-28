package egress

import (
	"errors"
	"net"
	"testing"
)

func TestIsDialableIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// Blocked (non-global / internal).
		{"127.0.0.1", false},       // loopback
		{"::1", false},             // loopback v6
		{"0.0.0.0", false},         // unspecified
		{"10.0.0.1", false},        // RFC1918
		{"172.16.5.4", false},      // RFC1918
		{"192.168.1.1", false},     // RFC1918
		{"169.254.169.254", false}, // link-local: cloud metadata
		{"fe80::1", false},         // link-local v6
		{"fc00::1", false},         // ULA private v6
		{"224.0.0.1", false},       // multicast
		{"100.64.0.1", false},      // CGNAT low edge
		{"100.100.100.200", false}, // CGNAT (Alibaba metadata)
		{"100.127.255.255", false}, // CGNAT high edge
		// Allowed (public global unicast).
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"100.63.255.255", true}, // just below CGNAT
		{"100.128.0.1", true},    // just above CGNAT
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isDialableIP(ip); got != c.want {
			t.Errorf("isDialableIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSafeDialTargetBlocksInternalLiterals(t *testing.T) {
	blocked := []string{
		"127.0.0.1:80",
		"169.254.169.254:80", // cloud metadata
		"10.1.2.3:443",
		"192.168.0.1:22",
		"100.100.100.200:80", // CGNAT metadata
		"[::1]:80",
	}
	for _, target := range blocked {
		_, err := safeDialTarget(target)
		if !errors.Is(err, errBlockedTarget) {
			t.Errorf("safeDialTarget(%q) err = %v, want errBlockedTarget", target, err)
		}
	}
}

func TestSafeDialTargetRejectsMalformed(t *testing.T) {
	if _, err := safeDialTarget("no-port-here"); err == nil {
		t.Fatal("expected error for target without a port")
	} else if errors.Is(err, errBlockedTarget) {
		t.Fatal("malformed target should not be reported as an SSRF block")
	}
}
