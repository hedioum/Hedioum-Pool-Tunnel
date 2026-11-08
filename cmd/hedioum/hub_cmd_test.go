package main

import (
	"strings"
	"testing"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
)

func reverseTok(ip, key string, port int) string {
	return pairing.Encode(pairing.Token{ExitIP: ip, AuthKey: key, SNI: "t.example.com", Endpoints: map[string]int{"https-alt": port}, Reverse: true})
}

func TestAddHubKeepsTheFirstHubAndAddsASecond(t *testing.T) {
	own := "0123456789abcdef0123456789abcdef"
	cfg := &config.AppConfig{Role: "foreign", AuthToken: own}

	// First hub of a normal foreign: reverse-only, fixed pipes by default.
	h1, err := applyAddHub(cfg, reverseTok("198.51.100.1", own, 8443), "ir1", 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if h1.MinConns != 12 || h1.MaxConns != 12 || h1.AuthToken != "" || !cfg.ReverseOnly {
		t.Fatalf("first hub: %+v reverseOnly=%v", h1, cfg.ReverseOnly)
	}

	// Second hub with its own range and a different node token.
	other := "fedcba9876543210fedcba9876543210"
	h2, err := applyAddHub(cfg, reverseTok("198.51.100.2", other, 443), "ir2", 4, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if h2.AuthToken != other || h2.MinConns != 4 || h2.MaxConns != 10 {
		t.Fatalf("second hub: %+v", h2)
	}
	if cfg.AuthToken != own {
		t.Fatal("adding a hub must not change the foreign's own token")
	}
	if got := cfg.EffectiveReverseHubs(); len(got) != 2 || got[1].AuthToken != other || got[0].AuthToken != own {
		t.Fatalf("effective hubs: %+v", got)
	}
	// Legacy fields stay usable for an older binary: sum of minimums, both targets.
	if cfg.ReverseConns != 16 || len(cfg.ReverseTargets) != 2 {
		t.Fatalf("compat: conns=%d targets=%+v", cfg.ReverseConns, cfg.ReverseTargets)
	}
}

func TestAddHubPromotesTheLegacySingleHub(t *testing.T) {
	own := "0123456789abcdef0123456789abcdef"
	cfg := &config.AppConfig{Role: "foreign", AuthToken: own, ReverseOnly: true, ReverseConns: 9,
		ReverseTargets: []config.Endpoint{{Target: "198.51.100.1:8443", Mimic: "https-alt"}}}
	if _, err := applyAddHub(cfg, reverseTok("198.51.100.2", own, 8443), "second", 3, 5, false); err != nil {
		t.Fatal(err)
	}
	hubs := cfg.EffectiveReverseHubs()
	if len(hubs) != 2 || hubs[0].Name != "default" || hubs[0].MinConns != 9 || hubs[0].MaxConns != 9 || hubs[1].Name != "second" {
		t.Fatalf("hubs after promotion: %+v", hubs)
	}
}

func TestAddHubRejections(t *testing.T) {
	own := "0123456789abcdef0123456789abcdef"
	cfg := &config.AppConfig{Role: "foreign", AuthToken: own}
	if _, err := applyAddHub(cfg, "nonsense", "x", 0, 0, false); err == nil {
		t.Error("garbage token must fail")
	}
	normal := pairing.Encode(pairing.Token{ExitIP: "1.2.3.4", AuthKey: own, Endpoints: map[string]int{"https-alt": 8443}})
	if _, err := applyAddHub(cfg, normal, "x", 0, 0, false); err == nil {
		t.Error("a normal (non-reverse) token must fail")
	}
	if _, err := applyAddHub(cfg, reverseTok("1.2.3.4", own, 8443), "x", 5, 3, false); err == nil {
		t.Error("max below min must fail")
	}
	if _, err := applyAddHub(cfg, reverseTok("1.2.3.4", own, 8443), "has space", 0, 0, false); err == nil {
		t.Error("a name with a space must fail")
	}
	if _, err := applyAddHub(cfg, reverseTok("1.2.3.4", own, 8443), "a", 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := applyAddHub(cfg, reverseTok("1.2.3.4", own, 8443), "b", 0, 0, false); err == nil || !strings.Contains(err.Error(), "already dials") {
		t.Errorf("the same hub under another name must fail, got %v", err)
	}
}

func TestEditAndRemoveHub(t *testing.T) {
	own := "0123456789abcdef0123456789abcdef"
	cfg := &config.AppConfig{Role: "foreign", AuthToken: own}
	_, _ = applyAddHub(cfg, reverseTok("198.51.100.1", own, 8443), "a", 3, 6, false)
	_, _ = applyAddHub(cfg, reverseTok("198.51.100.2", own, 8443), "b", 3, 6, false)

	if err := applyEditHub(cfg, "a", 0, 20); err != nil {
		t.Fatal(err)
	}
	if h := cfg.EffectiveReverseHubs()[0]; h.MinConns != 3 || h.MaxConns != 20 {
		t.Fatalf("0 keeps min and sets max: %+v", h)
	}
	if err := applyEditHub(cfg, "a", 30, 0); err != nil {
		t.Fatal(err) // raising min above the old max raises max with it
	}
	if h := cfg.EffectiveReverseHubs()[0]; h.MinConns != 30 || h.MaxConns != 30 {
		t.Fatalf("min above max: %+v", h)
	}
	if err := applyEditHub(cfg, "zzz", 3, 4); err == nil {
		t.Error("unknown hub must fail")
	}
	if err := applyEditHub(cfg, "a", 3, 1000); err == nil {
		t.Error("absurd max must fail")
	}

	if err := applyRemoveHub(cfg, "a"); err != nil {
		t.Fatal(err)
	}
	if cfg.ReverseConns != 3 || len(cfg.ReverseTargets) != 1 {
		t.Fatalf("compat not refreshed: conns=%d targets=%+v", cfg.ReverseConns, cfg.ReverseTargets)
	}
	if err := applyRemoveHub(cfg, "b"); err == nil {
		t.Error("the last hub cannot be removed with remove-hub")
	}
}

func TestReverseForeignResetsHubs(t *testing.T) {
	own := "0123456789abcdef0123456789abcdef"
	cfg := &config.AppConfig{Role: "foreign", AuthToken: own}
	_, _ = applyAddHub(cfg, reverseTok("198.51.100.1", own, 8443), "a", 3, 6, false)
	_, _ = applyAddHub(cfg, reverseTok("198.51.100.2", own, 8443), "b", 3, 6, false)

	if _, _, err := applyReverseForeign(cfg, reverseTok("198.51.100.3", own, 8443), 0, false); err == nil || !strings.Contains(err.Error(), "add-hub") {
		t.Fatalf("reverse-foreign over several hubs must point to add-hub, got %v", err)
	}
	if err := applyForwardForeign(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.ReverseHubs) != 0 || len(cfg.ReverseTargets) != 0 || cfg.ReverseOnly || len(cfg.EffectiveReverseHubs()) != 0 {
		t.Fatalf("--forward must clear every hub: %+v", cfg)
	}
}

func TestSetNodeBehindProxy(t *testing.T) {
	node := config.ForeignNode{Alias: "n", Endpoints: []config.Endpoint{
		{Target: "203.0.113.5:22", Mimic: "ssh"},
		{Target: "203.0.113.5:8443", Mimic: "https-alt", ServerName: "old.example.com"},
		{Target: "203.0.113.5:465", Mimic: "smtps", ServerName: "old.example.com"},
	}}
	if err := setNodeBehindProxy(&node, "https-alt", 443, "t.example.com"); err != nil {
		t.Fatal(err)
	}
	if ep := node.Endpoints[1]; ep.Target != "203.0.113.5:443" || ep.ServerName != "t.example.com" {
		t.Fatalf("endpoint not updated: %+v", ep)
	}
	if node.Endpoints[0].Target != "203.0.113.5:22" || node.Endpoints[2].Target != "203.0.113.5:465" || node.Endpoints[2].ServerName != "old.example.com" {
		t.Fatalf("other endpoints must be untouched: %+v", node.Endpoints)
	}
	for name, fn := range map[string]func() error{
		"ssh":      func() error { return setNodeBehindProxy(&node, "ssh", 443, "x") },
		"no sni":   func() error { return setNodeBehindProxy(&node, "https-alt", 443, "") },
		"bad port": func() error { return setNodeBehindProxy(&node, "https-alt", 0, "x") },
		"no mimic": func() error { return setNodeBehindProxy(&node, "imaps", 443, "x") },
		"reverse":  func() error { rn := node; rn.Reverse = true; return setNodeBehindProxy(&rn, "https-alt", 443, "x") },
	} {
		if err := fn(); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestNodeBehindProxyAndForeignProxyState(t *testing.T) {
	direct := config.ForeignNode{Endpoints: []config.Endpoint{{Target: "1.2.3.4:8443", Mimic: "https-alt", ServerName: "x.example.com"}}}
	proxied := config.ForeignNode{Endpoints: []config.Endpoint{{Target: "1.2.3.4:443", Mimic: "https-alt", ServerName: "x.example.com"}}}
	noSNI := config.ForeignNode{Endpoints: []config.Endpoint{{Target: "1.2.3.4:443", Mimic: "https-alt"}}}
	if nodeBehindProxy(direct) || !nodeBehindProxy(proxied) || nodeBehindProxy(noSNI) {
		t.Fatalf("direct=%v proxied=%v noSNI=%v", nodeBehindProxy(direct), nodeBehindProxy(proxied), nodeBehindProxy(noSNI))
	}
	if foreignProxyOn(&config.AppConfig{}) {
		t.Error("a plain foreign has no front proxy")
	}
	if !foreignProxyOn(&config.AppConfig{AdvertisePorts: map[string]int{"tls": 443}}) || !foreignProxyOn(&config.AppConfig{ListenBind: "127.0.0.1"}) {
		t.Error("advertised ports or a loopback bind mean the proxy is on")
	}
}
