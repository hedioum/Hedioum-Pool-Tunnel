package main

import (
	"reflect"
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
	plan, err := planReverseFor(cfg, &cfg.ForeignNodes[0], nil, "", true)
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

// A node flipped to reverse gets ONE listener, the TLS mimic, whatever its own mimic set
// is: every extra public listener on the hub is one more port to probe, and SSH cannot be
// used in reverse. Extra types are opt-in and a re-plan keeps what the node already has.
func TestPlanReverseDefaultsToOneTLSListener(t *testing.T) {
	fakePortsInUse(t)
	n := planTestNode("a",
		config.Endpoint{Target: "1.2.3.4:22", Mimic: "ssh"},
		config.Endpoint{Target: "1.2.3.4:465", Mimic: "smtps"},
		config.Endpoint{Target: "1.2.3.4:8443", Mimic: "https-alt"},
	)
	cfg := &config.AppConfig{Role: "iran", ForeignNodes: []config.ForeignNode{n}}
	plan, err := planReverse(cfg, &cfg.ForeignNodes[0], nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Listeners) != 1 || plan.Listeners[0].Type != "tls" {
		t.Fatalf("default must be a single tls listener, got %+v", plan.Listeners)
	}
	// Opt in to more by naming them, or take the node's whole set.
	plan, err = planReverse(cfg, &cfg.ForeignNodes[0], map[string]int{"smtps": 465}, "")
	if err != nil || len(plan.Listeners) != 2 || plan.Endpoints["smtps"] != 465 || plan.Endpoints["tls"] == 0 {
		t.Fatalf("a named type must be added: %+v err=%v", plan.Endpoints, err)
	}
	plan, err = planReverseFor(cfg, &cfg.ForeignNodes[0], nil, "", true)
	if err != nil || len(plan.Listeners) != 2 || plan.Endpoints["smtps"] == 0 || plan.Endpoints["https-alt"] == 0 {
		t.Fatalf("all types must be the node's own set minus ssh: %+v err=%v", plan.Endpoints, err)
	}
	// A node that is already reverse keeps the listener types it has.
	cfg.ForeignNodes[0].Reverse = true
	cfg.ForeignNodes[0].ReverseListeners = []config.MimicListener{{Type: "smtps", Port: 465}, {Type: "https-alt", Port: 8443}}
	plan, err = planReverse(cfg, &cfg.ForeignNodes[0], nil, "")
	if err != nil || len(plan.Listeners) != 2 || plan.Endpoints["smtps"] == 0 || plan.Endpoints["https-alt"] == 0 {
		t.Fatalf("a re-plan must keep the node's reverse types: %+v err=%v", plan.Endpoints, err)
	}
}
