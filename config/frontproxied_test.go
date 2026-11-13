package config

import "testing"

func TestFrontProxied(t *testing.T) {
	// Nothing configured: nobody is behind a proxy.
	if (&AppConfig{}).FrontProxied("tls") {
		t.Fatal("no front proxy settings means no proxied listener")
	}
	// Older rule: with no advertised ports, every TLS listener follows the bind.
	legacy := &AppConfig{ListenBind: "127.0.0.1"}
	if !legacy.FrontProxied("tls") || !legacy.FrontProxied("smtps") {
		t.Fatal("without advertised ports every non-SSH listener follows the bind")
	}
	// Per-type: only the advertised ones.
	c := &AppConfig{ListenBind: "127.0.0.1", ProxyProtocol: true, AdvertisePorts: map[string]int{"tls": 443}}
	if !c.FrontProxied("tls") || c.FrontProxied("smtps") {
		t.Fatal("only advertised types are behind the proxy")
	}
	// SSH is never proxied.
	if legacy.FrontProxied("ssh") || c.FrontProxied("ssh") {
		t.Fatal("SSH has no SNI and must never be proxied")
	}
}
