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

func multiMimicCfg() *config.AppConfig {
	return &config.AppConfig{
		Role: "foreign", AuthToken: "0123456789abcdef0123456789abcdef",
		Mimics: []config.MimicListener{
			{Type: "ssh", Port: 22},
			{Type: "tls", Port: 443, ServerName: "i1.example.test"},
			{Type: "https-alt", Port: 8443},
			{Type: "imap", Port: 143},
			{Type: "cpanel", Port: 2020},
		},
	}
}

func portOfType(cfg *config.AppConfig, ty string) int {
	for _, m := range cfg.Mimics {
		if m.Type == ty {
			return m.Port
		}
	}
	return 0
}

// One step puts several mimics behind the proxy: each keeps its public port and listens
// on public+40000 on loopback.
func TestAutoFrontProxyAssignsPorts(t *testing.T) {
	cfg := multiMimicCfg()
	if _, err := autoFrontProxy(cfg, []string{"all"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	for ty, want := range map[string]int{"tls": 40443, "https-alt": 48443, "imap": 40143, "cpanel": 42020} {
		if got := portOfType(cfg, ty); got != want {
			t.Errorf("%s listens on %d, want %d", ty, got, want)
		}
	}
	for ty, want := range map[string]int{"tls": 443, "https-alt": 8443, "imap": 143, "cpanel": 2020} {
		if cfg.AdvertisePorts[ty] != want {
			t.Errorf("%s advertised as %d, want %d (the public port a hub dials)", ty, cfg.AdvertisePorts[ty], want)
		}
	}
	if portOfType(cfg, "ssh") != 22 || cfg.AdvertisePorts["ssh"] != 0 {
		t.Error("SSH must be left alone")
	}
	if cfg.ListenBind != "127.0.0.1" || !cfg.ProxyProtocol {
		t.Errorf("bind/proxy protocol not set: %q %v", cfg.ListenBind, cfg.ProxyProtocol)
	}
	// Running it again changes nothing.
	if _, err := autoFrontProxy(cfg, []string{"all"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	if portOfType(cfg, "https-alt") != 48443 || cfg.AdvertisePorts["https-alt"] != 8443 {
		t.Fatal("a second run must be harmless")
	}
}

// Only the ticked types go behind the proxy; the rest stay public, and the firewall
// still opens the public ones.
func TestAutoFrontProxyOnlyChosenTypes(t *testing.T) {
	cfg := multiMimicCfg()
	if _, err := autoFrontProxy(cfg, []string{"tls", "https-alt"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	if portOfType(cfg, "imap") != 143 || portOfType(cfg, "cpanel") != 2020 {
		t.Fatal("unchosen types must keep their listener port")
	}
	if cfg.FrontProxied("imap") || !cfg.FrontProxied("tls") {
		t.Fatal("only the chosen types are behind the proxy")
	}
	open := map[int]bool{}
	for _, p := range firewallPorts(cfg) {
		open[p] = true
	}
	if !open[22] || !open[143] || !open[2020] {
		t.Fatalf("public listeners must stay open: %v", firewallPorts(cfg))
	}
	if open[40443] || open[48443] {
		t.Fatalf("listeners behind the proxy must not be opened: %v", firewallPorts(cfg))
	}
}

func TestAutoFrontProxyErrors(t *testing.T) {
	cfg := multiMimicCfg()
	if _, err := autoFrontProxy(cfg, []string{"ssh"}, defaultFrontProxyOffset, false); err == nil {
		t.Error("SSH cannot be put behind a proxy")
	}
	if _, err := autoFrontProxy(cfg, []string{"nope"}, defaultFrontProxyOffset, false); err == nil {
		t.Error("an unknown type must be rejected")
	}
	cfg = multiMimicCfg()
	cfg.Mimics[1].Port = 30000
	if _, err := autoFrontProxy(cfg, []string{"tls"}, defaultFrontProxyOffset, false); err == nil {
		t.Error("public port + offset above 65535 must be rejected")
	}
	cfg = multiMimicCfg()
	cfg.Mimics = append(cfg.Mimics, config.MimicListener{Type: "smtps", Port: 40443})
	if _, err := autoFrontProxy(cfg, []string{"tls"}, defaultFrontProxyOffset, false); err == nil {
		t.Error("a local port that another listener already uses must be rejected")
	}
	if _, err := autoFrontProxy(multiMimicCfg(), []string{"tls"}, 0, false); err == nil {
		t.Error("offset 0 must be rejected")
	}
}

// Taking a type back out restores its public port; when none is left, the bind and
// PROXY protocol are cleared.
func TestRemoveFrontProxy(t *testing.T) {
	cfg := multiMimicCfg()
	if _, err := autoFrontProxy(cfg, []string{"tls", "https-alt"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	if err := removeFrontProxy(cfg, []string{"https-alt"}); err != nil {
		t.Fatal(err)
	}
	if portOfType(cfg, "https-alt") != 8443 || cfg.FrontProxied("https-alt") {
		t.Fatal("a removed type must go back to its public port")
	}
	if cfg.ListenBind != "127.0.0.1" || !cfg.FrontProxied("tls") {
		t.Fatal("the other type stays behind the proxy")
	}
	if err := removeFrontProxy(cfg, []string{"tls"}); err != nil {
		t.Fatal(err)
	}
	if portOfType(cfg, "tls") != 443 || cfg.ListenBind != "" || cfg.ProxyProtocol || len(cfg.AdvertisePorts) != 0 {
		t.Fatalf("last type removed must clear the proxy settings: %+v", cfg)
	}
	if err := removeFrontProxy(cfg, []string{"tls"}); err == nil {
		t.Fatal("removing a type that is not behind the proxy must say so")
	}
}

// The type on the shared port is routed by SNI; the others get a port of their own and
// need no SNI.
func TestFrontProxyRoutesSharedPortBySNIAndOthersByPort(t *testing.T) {
	cfg := multiMimicCfg()
	if _, err := autoFrontProxy(cfg, []string{"tls", "https-alt", "imap"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	spec, err := foreignFrontSpec(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if spec.SNI != "i1.example.test" || spec.Upstream != "127.0.0.1:40443" {
		t.Fatalf("the shared-port listener must be routed by SNI: %+v", spec)
	}
	fw := foreignDedicatedForwards(cfg)
	if len(fw) != 2 || fw[0].Public != 143 || fw[1].Public != 8443 || fw[1].Upstream != "127.0.0.1:48443" {
		t.Fatalf("dedicated forwards wrong: %+v", fw)
	}
	ng := nginxDedicated(fw, true)
	for _, want := range []string{"listen 143;", "proxy_pass 127.0.0.1:40143;", "listen 8443;", "proxy_pass 127.0.0.1:48443;", "proxy_protocol on;"} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx forwards missing %q:\n%s", want, ng)
		}
	}
	if strings.Contains(ng, "ssl_preread") || strings.Contains(ng, "i1.example.test") {
		t.Errorf("a dedicated forward needs no SNI:\n%s", ng)
	}
	hp := haproxyDedicated(fw, true)
	for _, want := range []string{"bind :143", "bind :8443", "server hub 127.0.0.1:48443 send-proxy"} {
		if !strings.Contains(hp, want) {
			t.Errorf("haproxy forwards missing %q:\n%s", want, hp)
		}
	}
	// With nothing on the shared port there is no SNI listener, and no SNI is needed.
	cfg2 := multiMimicCfg()
	cfg2.Mimics[1].ServerName = ""
	if _, err := autoFrontProxy(cfg2, []string{"https-alt"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatalf("a dedicated port needs no SNI: %v", err)
	}
	if _, err := foreignFrontSpec(cfg2); err != errNoSNIListener {
		t.Fatalf("want errNoSNIListener, got %v", err)
	}
	// But the shared port does need one.
	cfg3 := multiMimicCfg()
	cfg3.Mimics[1].ServerName = ""
	if _, err := autoFrontProxy(cfg3, []string{"tls"}, defaultFrontProxyOffset, true); err == nil {
		t.Fatal("a listener on the shared port is routed by SNI and must need one")
	}
}

// Ports the operator already moved behind the proxy by hand are local ports: the public
// port is derived from them instead of adding the offset a second time.
func TestAutoFrontProxyKeepsHandMovedPorts(t *testing.T) {
	cfg := multiMimicCfg()
	cfg.ListenBind, cfg.ProxyProtocol = "127.0.0.1", true
	cfg.Mimics[3].Port = 40143 // imap, moved by hand
	cfg.Mimics[2].Port = 48443 // https-alt, moved by hand
	if _, err := autoFrontProxy(cfg, []string{"imap", "https-alt"}, defaultFrontProxyOffset, true); err != nil {
		t.Fatal(err)
	}
	if portOfType(cfg, "imap") != 40143 || cfg.AdvertisePorts["imap"] != 143 ||
		portOfType(cfg, "https-alt") != 48443 || cfg.AdvertisePorts["https-alt"] != 8443 {
		t.Fatalf("hand-moved ports must be kept: %+v %+v", cfg.Mimics, cfg.AdvertisePorts)
	}
}
