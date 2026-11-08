package main

import (
	"strings"
	"testing"

	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
)

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }

func foreignTestCfg() *config.AppConfig {
	return &config.AppConfig{
		Role: "foreign", AuthToken: "0123456789abcdef0123456789abcdef",
		Mimics: []config.MimicListener{
			{Type: "ssh", Port: 22},
			{Type: "tls", Port: 8443, ServerName: "i3.example.test"},
		},
	}
}

func TestParseTypePortList(t *testing.T) {
	got, err := parseTypePortList("tls=443, https-alt=8443,ssh=2222")
	if err != nil || got["tls"] != 443 || got["https-alt"] != 8443 || got["ssh"] != 2222 {
		t.Fatalf("got %v err=%v", got, err)
	}
	if m, err := parseTypePortList(""); err != nil || len(m) != 0 {
		t.Fatalf("empty must be an empty map: %v %v", m, err)
	}
	for _, bad := range []string{"tls", "tls=x", "tls=0", "nope=443"} {
		if _, err := parseTypePortList(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
	if got := formatTypePorts(map[string]int{"tls": 443, "https-alt": 8443}); got != "https-alt=8443,tls=443" {
		t.Fatalf("formatTypePorts = %q", got)
	}
}

func TestForeignFrontProxySettings(t *testing.T) {
	cfg := foreignTestCfg()
	warns, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: sp("127.0.0.1"), ProxyProtocol: bp(true), Advertise: map[string]int{"tls": 443}, AdvertiseSet: true})
	if err != nil || len(warns) != 0 {
		t.Fatalf("err=%v warns=%v", err, warns)
	}
	if cfg.ListenBind != "127.0.0.1" || !cfg.ProxyProtocol || cfg.AdvertisePorts["tls"] != 443 {
		t.Fatalf("not stored: %+v", cfg)
	}
	// Not touching the proxy flags keeps them.
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{}); err != nil || cfg.AdvertisePorts["tls"] != 443 {
		t.Fatalf("a no-op must keep the settings: %v %+v", err, cfg.AdvertisePorts)
	}
	// Rejections.
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Advertise: map[string]int{"ssh": 443}, AdvertiseSet: true}); err == nil {
		t.Error("SSH cannot be fronted by SNI")
	}
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Advertise: map[string]int{"smtps": 443}, AdvertiseSet: true}); err == nil {
		t.Error("advertising a type the foreign does not run must fail")
	}
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: sp("nope")}); err == nil {
		t.Error("an invalid bind must fail")
	}
	noSNI := foreignTestCfg()
	noSNI.Mimics[1].ServerName = ""
	if _, err := applyForeignFrontProxy(noSNI, foreignProxyOpts{Advertise: map[string]int{"tls": 443}, AdvertiseSet: true}); err == nil {
		t.Error("a front proxy needs an SNI")
	}
	// Unprotected listeners are warned about.
	loose := foreignTestCfg()
	warns, err = applyForeignFrontProxy(loose, foreignProxyOpts{ProxyProtocol: bp(true), Advertise: map[string]int{"tls": 443}, AdvertiseSet: true})
	if err != nil || len(warns) == 0 {
		t.Fatalf("expected warnings for a non-loopback bind: %v %v", err, warns)
	}
	// Clearing.
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: sp(""), ProxyProtocol: bp(false), AdvertiseSet: true}); err != nil {
		t.Fatal(err)
	}
	if cfg.ListenBind != "" || cfg.ProxyProtocol || cfg.AdvertisePorts != nil {
		t.Fatalf("clear failed: %+v", cfg)
	}
}

func TestForeignTokenAndSnippet(t *testing.T) {
	cfg := foreignTestCfg()
	if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: sp("127.0.0.1"), ProxyProtocol: bp(true), Advertise: map[string]int{"tls": 443}, AdvertiseSet: true}); err != nil {
		t.Fatal(err)
	}
	// The pairing token carries the advertised port, so the hub dials the proxy.
	tok := foreignPairingToken(cfg, "198.51.100.7")
	pt, isV2, err := pairing.Decode(tok)
	if err != nil || !isV2 || pt.Endpoints["tls"] != 443 || pt.Endpoints["ssh"] != 22 || pt.SNI != "i3.example.test" {
		t.Fatalf("token wrong: %+v err=%v", pt, err)
	}
	sp, err := foreignFrontSpec(cfg)
	if err != nil || sp.Upstream != "127.0.0.1:8443" || sp.SNI != "i3.example.test" || !sp.ProxyProtocol {
		t.Fatalf("spec = %+v err=%v", sp, err)
	}
	ng := nginxFor(sp, 443)
	if !strings.Contains(ng, "i3.example.test  127.0.0.1:8443;") || !strings.Contains(ng, "proxy_protocol on;") {
		t.Fatalf("nginx snippet wrong:\n%s", ng)
	}
	if hp := haproxyFor(sp, 443); !strings.Contains(hp, "send-proxy") {
		t.Fatalf("haproxy snippet wrong:\n%s", hp)
	}
	cfg.Mimics[1].ServerName, cfg.Domain = "", ""
	if _, err := foreignFrontSpec(cfg); err == nil {
		t.Fatal("no SNI: no spec")
	}
}

// A foreign whose listeners are bound to loopback opens nothing for them on the host
// firewall, except the SSH mimic, which is never bound to the proxy address.
func TestFirewallSkipsLoopbackBoundForeign(t *testing.T) {
	cfg := foreignTestCfg()
	if got := firewallPorts(cfg); len(got) == 0 {
		t.Fatal("a normal foreign must open its listener ports")
	}
	cfg.ListenBind = "127.0.0.1"
	got := firewallPorts(cfg)
	for _, p := range got {
		for _, m := range cfg.Mimics {
			if m.Port == p && m.Type != "ssh" {
				t.Fatalf("a loopback-bound %s listener must not be opened, got %v", m.Type, got)
			}
		}
	}
}

func TestFrontProxySnippetsWithoutProxyProtocol(t *testing.T) {
	spec := frontSpec{Upstream: "127.0.0.1:8443", SNI: "i3.example.test"}
	if ng := nginxFor(spec, 443); strings.Contains(ng, "        proxy_protocol on;") {
		t.Error("no PROXY protocol: the minimal stream server must not enable it")
	}
	if hp := haproxyFor(spec, 443); strings.Contains(hp, "send-proxy") || !strings.Contains(hp, "req_ssl_sni -i i3.example.test") {
		t.Errorf("haproxy config wrong:\n%s", hp)
	}
}

func TestForeignProxyOnState(t *testing.T) {
	if foreignProxyOn(&config.AppConfig{}) {
		t.Error("a plain foreign has no front proxy")
	}
	for name, cfg := range map[string]*config.AppConfig{
		"advertised port": {AdvertisePorts: map[string]int{"tls": 443}},
		"loopback bind":   {ListenBind: "127.0.0.1"},
		"proxy protocol":  {ProxyProtocol: true},
	} {
		if !foreignProxyOn(cfg) {
			t.Errorf("%s must count as the proxy being on", name)
		}
	}
}

// A hub-side proxy must send every node that shares the listener to the tunnel, taking
// each node's address from its endpoints (TargetIP can be empty or stale).
func TestNodeSourceIPsUseEndpointAddresses(t *testing.T) {
	l := []config.MimicListener{{Type: "tls", Port: 9553, ServerName: "t.example.test"}}
	a := config.ForeignNode{Alias: "a", TargetIP: "192.0.2.10", Reverse: true, ReverseListeners: l, ReverseBind: "127.0.0.1",
		Endpoints: []config.Endpoint{{Target: "192.0.2.10:22", Mimic: "ssh"}}}
	b := config.ForeignNode{Alias: "b", Reverse: true, ReverseListeners: l, ReverseBind: "127.0.0.1",
		Endpoints: []config.Endpoint{{Target: "198.51.100.7:22", Mimic: "ssh"}}}
	other := config.ForeignNode{Alias: "c", Reverse: true, ReverseBind: "127.0.0.1",
		ReverseListeners: []config.MimicListener{{Type: "tls", Port: 9999}},
		Endpoints:        []config.Endpoint{{Target: "203.0.113.5:22", Mimic: "ssh"}}}
	cfg := &config.AppConfig{ForeignNodes: []config.ForeignNode{a, b, other}}
	got := nodeSourceIPs(cfg, a)
	if len(got) != 2 || got[0] != "192.0.2.10" || got[1] != "198.51.100.7" {
		t.Fatalf("got %v, want both nodes of the shared listener and not the other one", got)
	}
}
