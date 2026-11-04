package main

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// nextPortWithTimeout fails the test instead of hanging if the search never returns.
func nextPortWithTimeout(t *testing.T, cfg *config.AppConfig) int {
	t.Helper()
	done := make(chan string, 1)
	go func() { done <- getNextFreeSocksPort(cfg) }()
	select {
	case s := <-done:
		p, err := strconv.Atoi(s)
		if err != nil || validPort(p) != nil {
			t.Fatalf("suggested port %q is not a valid port", s)
		}
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("getNextFreeSocksPort did not return (infinite loop, issue #37)")
		return 0
	}
}

func nodes(ports ...int) *config.AppConfig {
	cfg := &config.AppConfig{}
	for _, p := range ports {
		cfg.ForeignNodes = append(cfg.ForeignNodes, config.ForeignNode{LocalSocksPort: p})
	}
	return cfg
}

func TestNextFreeSocksPortNoHang(t *testing.T) {
	cases := map[string]*config.AppConfig{
		"none":          nodes(),
		"normal":        nodes(40001, 40002),
		"max port":      nodes(65535),
		"typo 400001":   nodes(40001, 400001),
		"negative/zero": nodes(-1, 0),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			p := nextPortWithTimeout(t, cfg)
			for _, n := range cfg.ForeignNodes {
				if n.LocalSocksPort == p {
					t.Fatalf("suggested %d, already used by a node", p)
				}
			}
		})
	}
}

func TestNextFreeSocksPortSkipsBusyPort(t *testing.T) {
	// Hold the port that would normally be suggested; the search must step past it.
	want := nextPortWithTimeout(t, nodes(40001))
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(want))
	if err != nil {
		t.Skipf("cannot bind %d: %v", want, err)
	}
	defer ln.Close()
	if got := nextPortWithTimeout(t, nodes(40001)); got == want {
		t.Fatalf("suggested busy port %d", got)
	}
}

func TestValidatePortInput(t *testing.T) {
	for in, ok := range map[string]bool{
		"": true, "40001": true, " 22 ": true, "65535": true,
		"0": false, "65536": false, "400001": false, "-5": false, "abc": false,
	} {
		if err := validatePortInput(in); (err == nil) != ok {
			t.Errorf("validatePortInput(%q) err=%v, want ok=%v", in, err, ok)
		}
	}
}
