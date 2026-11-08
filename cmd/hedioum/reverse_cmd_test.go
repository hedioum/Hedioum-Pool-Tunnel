package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

func TestReverseCapableTypesDropsSSH(t *testing.T) {
	got := reverseCapableTypes([]string{"ssh", "tls", "bogus", "smtps"})
	want := []string{"tls", "smtps"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParsePortOverrides(t *testing.T) {
	got, err := parsePortOverrides("tls=8443, smtps=2465")
	if err != nil {
		t.Fatal(err)
	}
	if got["tls"] != 8443 || got["smtps"] != 2465 || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if m, err := parsePortOverrides(""); err != nil || len(m) != 0 {
		t.Fatalf("empty spec must give an empty map, got %v err=%v", m, err)
	}
	for _, bad := range []string{"tls", "tls=abc", "tls=0", "tls=70000", "ssh=22", "nope=443"} {
		if _, err := parsePortOverrides(bad); err == nil {
			t.Errorf("parsePortOverrides(%q) should fail", bad)
		}
	}
}

func TestReverseFirewallPorts(t *testing.T) {
	cfg := &config.AppConfig{ForeignNodes: []config.ForeignNode{
		{Alias: "fwd"}, // normal node: no public listener
		{Alias: "a", Reverse: true, ReverseListeners: []config.MimicListener{{Type: "tls", Port: 443}, {Type: "https-alt", Port: 8443}}},
		{Alias: "b", Reverse: true, ReverseListeners: []config.MimicListener{{Type: "tls", Port: 443}, {Type: "smtps", Port: 465}}},
	}}
	got := reverseFirewallPorts(cfg)
	want := []int{443, 465, 8443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := reverseFirewallPorts(&config.AppConfig{}); len(got) != 0 {
		t.Fatalf("a hub without reverse nodes opens nothing, got %v", got)
	}
}

func fakePortsInUse(t *testing.T, used ...int) {
	t.Helper()
	old := portInUse
	portInUse = func(p int) bool {
		for _, u := range used {
			if u == p {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { portInUse = old })
}

func planTestNode(alias string, eps ...config.Endpoint) config.ForeignNode {
	return config.ForeignNode{Alias: alias, AuthToken: "0123456789abcdef0123456789abcdef", Endpoints: eps}
}

// A node whose port is free keeps it; a port taken on the host (443 here) moves to a
// free candidate, and the move is reported.
func TestPlanReverseMovesTakenPorts(t *testing.T) {
	fakePortsInUse(t, 443)
	n := planTestNode("a",
		config.Endpoint{Target: "1.2.3.4:443", Mimic: "tls"},
		config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"},
	)
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}
	plan, err := planReverse(cfg, &cfg.ForeignNodes[0], nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Endpoints["https-alt"] != 8443 {
		t.Fatalf("a free port must be kept: %v", plan.Endpoints)
	}
	tlsPort := plan.Endpoints["tls"]
	if tlsPort == 443 || tlsPort == 8443 || tlsPort == 0 {
		t.Fatalf("tls must move to a free, distinct port, got %d", tlsPort)
	}
	if plan.Moved["tls"] != 443 || len(plan.Moved) != 1 {
		t.Fatalf("moved = %v", plan.Moved)
	}
}

func TestPlanReverseExplicitPortInUseIsAnError(t *testing.T) {
	fakePortsInUse(t, 443)
	n := planTestNode("a", config.Endpoint{Target: "1.2.3.4:443", Mimic: "tls"})
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}
	if _, err := planReverse(cfg, &cfg.ForeignNodes[0], map[string]int{"tls": 443}, ""); err == nil {
		t.Fatal("an explicitly requested port that is taken must fail")
	}
}

// A second reverse node never reuses the first one's ports, and a node that is
// already reverse does not see its own listeners as a conflict.
func TestPlanReverseAvoidsOtherNodesAndOwnListeners(t *testing.T) {
	fakePortsInUse(t, 8443) // held by node "a"'s own running listener
	a := planTestNode("a", config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"})
	a.Reverse = true
	a.ReverseListeners = []config.MimicListener{{Type: "https-alt", Port: 8443}}
	b := planTestNode("b", config.Endpoint{Target: "5.6.7.8:8443", Mimic: "https-alt"})
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{a, b}}

	planB, err := planReverse(cfg, &cfg.ForeignNodes[1], nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if planB.Endpoints["https-alt"] == 8443 {
		t.Fatal("node b must not take node a's port")
	}
	planA, err := planReverse(cfg, &cfg.ForeignNodes[0], nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if planA.Endpoints["https-alt"] != 8443 || len(planA.Moved) != 0 {
		t.Fatalf("a re-plan must keep node a's own port: %+v", planA)
	}
}

func TestApplyReverseIranAndForward(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a", config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"})
	other := planTestNode("keep", config.Endpoint{Target: "9.9.9.9:443", Mimic: "tls"})
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n, other}}

	plan, tok, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ForeignNodes[0].Reverse || len(plan.Listeners) != 1 || tok == "" {
		t.Fatalf("node a not flipped: %+v tok=%q", cfg.ForeignNodes[0], tok)
	}
	if cfg.ForeignNodes[1].Reverse {
		t.Fatal("other nodes must stay in the normal mode")
	}
	if _, _, err := applyReverseIran(cfg, "nope", nil, "198.51.100.7", reverseOpts{}); err == nil {
		t.Fatal("unknown alias must fail")
	}

	// The foreign side consumes that token.
	fcfg := &config.AppConfig{Role: "foreign", AuthToken: "old"}
	cnt, changed, err := applyReverseForeign(fcfg, tok, 0, false)
	if err != nil || cnt != 1 || !changed {
		t.Fatalf("foreign apply: n=%d changed=%v err=%v", cnt, changed, err)
	}
	if !fcfg.ReverseOnly || len(fcfg.ReverseTargets) != 1 || fcfg.AuthToken != n.AuthToken {
		t.Fatalf("foreign config wrong: %+v", fcfg)
	}
	if err := applyForwardForeign(fcfg); err != nil || len(fcfg.ReverseTargets) != 0 || fcfg.ReverseOnly {
		t.Fatalf("foreign forward: %v %+v", err, fcfg)
	}
	if err := applyForwardForeign(fcfg); err == nil {
		t.Fatal("forward on an already-normal foreign must fail")
	}

	if err := applyForwardIran(cfg, "a"); err != nil || cfg.ForeignNodes[0].Reverse || cfg.ForeignNodes[0].ReverseListeners != nil {
		t.Fatalf("hub forward: %v %+v", err, cfg.ForeignNodes[0])
	}
	if err := applyForwardIran(cfg, "a"); err == nil {
		t.Fatal("forward on an already-normal node must fail")
	}
}

func TestApplyReverseForeignRejectsNormalToken(t *testing.T) {
	if _, _, err := applyReverseForeign(&config.AppConfig{Role: "foreign"}, "garbage", 0, false); err == nil {
		t.Fatal("a non-token must be rejected")
	}
}

// The SNI and decoy persona of the foreign carry over: SNI lands in the token and the
// listeners, the decoy on the node, and going back to normal clears the decoy.
func TestApplyReverseCarriesSNIAndDecoy(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a", config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt", ServerName: "old.example"})
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}

	// Default: the node's current SNI is kept.
	plan, _, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{})
	if err != nil || plan.SNI != "old.example" || plan.Listeners[0].ServerName != "old.example" {
		t.Fatalf("current SNI must carry over: %+v err=%v", plan, err)
	}
	// Override both.
	plan, tok, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{SNI: "new.example", Decoy: "directadmin"})
	if err != nil || plan.SNI != "new.example" || plan.Listeners[0].ServerName != "new.example" {
		t.Fatalf("SNI override: %+v err=%v", plan, err)
	}
	if cfg.ForeignNodes[0].ReverseDecoyStyle != "directadmin" {
		t.Fatalf("decoy not stored: %q", cfg.ForeignNodes[0].ReverseDecoyStyle)
	}
	fcfg := &config.AppConfig{Role: "foreign"}
	if _, _, err := applyReverseForeign(fcfg, tok, 0, false); err != nil {
		t.Fatal(err)
	}
	if fcfg.ReverseTargets[0].ServerName != "new.example" {
		t.Fatalf("the foreign must send the SNI: %+v", fcfg.ReverseTargets)
	}
	if _, _, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{Decoy: "nginx"}); err == nil {
		t.Fatal("an unknown decoy style must be rejected")
	}
	if err := applyForwardIran(cfg, "a"); err != nil || cfg.ForeignNodes[0].ReverseDecoyStyle != "" {
		t.Fatalf("forward must clear the decoy: %v %q", err, cfg.ForeignNodes[0].ReverseDecoyStyle)
	}
}

// With a front proxy the foreign is told a different port than the hub listens on.
func TestApplyReverseAdvertisePorts(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a", config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"})
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}
	plan, tok, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{Advertise: map[string]int{"https-alt": 443}, AdvertiseSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Listeners[0].Port != 8443 || cfg.ForeignNodes[0].ReverseListeners[0].Port != 8443 {
		t.Fatalf("the hub must still listen on 8443: %+v", plan.Listeners)
	}
	fcfg := &config.AppConfig{Role: "foreign"}
	if _, _, err := applyReverseForeign(fcfg, tok, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := fcfg.ReverseTargets[0].Target; got != "198.51.100.7:443" {
		t.Fatalf("the foreign must dial the advertised port, got %s", got)
	}
	if _, _, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{Advertise: map[string]int{"tls": 443}, AdvertiseSet: true}); err == nil {
		t.Fatal("advertising a type the node has no listener for must fail")
	}
}

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }

// Front-proxy settings are remembered across re-runs, only advertised types are served,
// and going back to the normal mode clears them.
func TestFrontProxySettingsPersist(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a",
		config.Endpoint{Target: "1.2.3.4:443", Mimic: "tls", ServerName: "i3.example.test"},
		config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt", ServerName: "i3.example.test"},
	)
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}

	plan, tok, err := applyReverseIran(cfg, "a", map[string]int{"tls": 9443, "https-alt": 8443}, "198.51.100.7", reverseOpts{
		Advertise: map[string]int{"https-alt": 443}, AdvertiseSet: true, Bind: sp("127.0.0.1"), ProxyProtocol: bp(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	node := cfg.ForeignNodes[0]
	if len(plan.Listeners) != 1 || plan.Listeners[0].Type != "https-alt" {
		t.Fatalf("only the advertised type is served behind a proxy: %+v", plan.Listeners)
	}
	if node.ReverseBind != "127.0.0.1" || !node.ReverseProxyProtocol || node.ReverseAdvertise["https-alt"] != 443 {
		t.Fatalf("settings not stored: %+v", node)
	}
	fcfg := &config.AppConfig{Role: "foreign"}
	if n, _, err := applyReverseForeign(fcfg, tok, 0, false); err != nil || n != 1 || fcfg.ReverseTargets[0].Target != "198.51.100.7:443" {
		t.Fatalf("foreign must dial the advertised port only: %v %+v", err, fcfg.ReverseTargets)
	}

	// Re-run without the flags: everything is kept.
	if _, _, err := applyReverseIran(cfg, "a", map[string]int{"https-alt": 8443}, "198.51.100.7", reverseOpts{SNI: "i3.example.test"}); err != nil {
		t.Fatal(err)
	}
	node = cfg.ForeignNodes[0]
	if node.ReverseBind != "127.0.0.1" || !node.ReverseProxyProtocol || node.ReverseAdvertise["https-alt"] != 443 {
		t.Fatalf("a re-run without flags must keep the front-proxy settings: %+v", node)
	}

	// Explicit clear.
	if _, _, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{AdvertiseSet: true, Bind: sp(""), ProxyProtocol: bp(false)}); err != nil {
		t.Fatal(err)
	}
	node = cfg.ForeignNodes[0]
	if node.ReverseBind != "" || node.ReverseProxyProtocol || len(node.ReverseAdvertise) != 0 {
		t.Fatalf("explicit clear failed: %+v", node)
	}

	// Forward clears whatever is left.
	cfg.ForeignNodes[0].ReverseBind, cfg.ForeignNodes[0].ReverseProxyProtocol = "127.0.0.1", true
	cfg.ForeignNodes[0].ReverseAdvertise = map[string]int{"https-alt": 443}
	if err := applyForwardIran(cfg, "a"); err != nil {
		t.Fatal(err)
	}
	node = cfg.ForeignNodes[0]
	if node.ReverseBind != "" || node.ReverseProxyProtocol || node.ReverseAdvertise != nil {
		t.Fatalf("forward must clear front-proxy settings: %+v", node)
	}
}

func TestAdvertiseSamePortTwiceIsRejected(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a",
		config.Endpoint{Target: "1.2.3.4:443", Mimic: "tls"},
		config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"},
	)
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}
	_, _, err := applyReverseIran(cfg, "a", map[string]int{"tls": 9443, "https-alt": 8443}, "198.51.100.7", reverseOpts{
		Advertise: map[string]int{"tls": 443, "https-alt": 443}, AdvertiseSet: true,
	})
	if err == nil {
		t.Fatal("two types on one public port cannot be told apart by a proxy and must be rejected")
	}
	if _, _, err := applyReverseIran(cfg, "a", nil, "198.51.100.7", reverseOpts{Bind: sp("not-an-ip")}); err == nil {
		t.Fatal("an invalid bind address must be rejected")
	}
}

// A loopback-bound node is not reachable from outside, so the host firewall opens nothing for it.
func TestFirewallSkipsLoopbackBoundNodes(t *testing.T) {
	cfg := &config.AppConfig{ForeignNodes: []config.ForeignNode{
		{Alias: "proxied", Reverse: true, ReverseBind: "127.0.0.1", ReverseListeners: []config.MimicListener{{Type: "https-alt", Port: 8443}}},
		{Alias: "open", Reverse: true, ReverseListeners: []config.MimicListener{{Type: "tls", Port: 2053}}},
	}}
	if got := reverseFirewallPorts(cfg); !reflect.DeepEqual(got, []int{2053}) {
		t.Fatalf("got %v, want only the publicly bound port", got)
	}
}

func TestFrontProxySnippets(t *testing.T) {
	node := config.ForeignNode{
		Alias: "a", Reverse: true, ReverseBind: "127.0.0.1", ReverseProxyProtocol: true,
		ReverseListeners: []config.MimicListener{{Type: "https-alt", Port: 8443, ServerName: "i3.example.test"}},
	}
	ng, err := nginxSnippet(node, 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"i3.example.test  127.0.0.1:8443;", "proxy_protocol on;", "listen 443;"} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx snippet is missing %q:\n%s", want, ng)
		}
	}
	hp, err := haproxySnippet(node, 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"req_ssl_sni -i i3.example.test", "server hub 127.0.0.1:8443 send-proxy"} {
		if !strings.Contains(hp, want) {
			t.Errorf("haproxy snippet is missing %q:\n%s", want, hp)
		}
	}
	node.ReverseProxyProtocol = false
	if ng, _ = nginxSnippet(node, 443); strings.Contains(ng, "        proxy_protocol on;") {
		t.Error("no PROXY protocol: the minimal stream server must not enable it")
	}
	if hp, _ = haproxySnippet(node, 443); strings.Contains(hp, "send-proxy") {
		t.Error("no PROXY protocol: HAProxy must not send it")
	}
	if _, err := nginxSnippet(config.ForeignNode{Alias: "x"}, 443); err == nil {
		t.Error("a node that is not reverse has no front-proxy config")
	}
	node.ReverseListeners[0].ServerName = ""
	if _, err := nginxSnippet(node, 443); err == nil {
		t.Error("without an SNI the proxy cannot recognise the tunnel")
	}
}
