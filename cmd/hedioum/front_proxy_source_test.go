package main

import (
	"strings"
	"testing"
)

// Routing by source IP lets the tunnel share an SNI with a real service: the listed
// addresses go to the tunnel, everyone else keeps following the SNI map.
func TestFrontProxyBySourceSnippets(t *testing.T) {
	sp := frontSpec{Upstream: "127.0.0.1:8443", SNI: "i1.example.test", ProxyProtocol: true, Sources: []string{"203.0.113.10", "203.0.113.20"}}
	ng := nginxFor(sp, 443)
	for _, want := range []string{
		"map $remote_addr $tunnel_or_sni {", "203.0.113.10  127.0.0.1:8443;", "203.0.113.20  127.0.0.1:8443;",
		"default  $by_sni;", "proxy_pass $tunnel_or_sni;", "proxy_protocol on;",
	} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx by-source config is missing %q:\n%s", want, ng)
		}
	}
	hp := haproxyFor(sp, 443)
	if !strings.Contains(hp, "use_backend hedioum if { src 203.0.113.10 203.0.113.20 }") || strings.Contains(hp, "req_ssl_sni") {
		t.Errorf("haproxy by-source rule wrong:\n%s", hp)
	}
	if !strings.Contains(hp, "server hub 127.0.0.1:8443 send-proxy") {
		t.Errorf("haproxy must keep send-proxy:\n%s", hp)
	}
	// Without sources nothing changes.
	sp.Sources = nil
	if ng = nginxFor(sp, 443); strings.Contains(ng, "$remote_addr") {
		t.Error("SNI routing must not mention the source address")
	}
}

func TestParseSourceIPs(t *testing.T) {
	got, err := parseSourceIPs("203.0.113.10, 203.0.113.10,2001:db8::1")
	if err != nil || len(got) != 2 || got[1] != "2001:db8::1" {
		t.Fatalf("got %v err %v", got, err)
	}
	for _, bad := range []string{"nope", "10.0.0.0/8", "1.2.3"} {
		if _, err := parseSourceIPs(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
