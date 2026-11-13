package config

import "testing"

// A foreign in reverse-only mode must not get the legacy SSH listener synthesized
// (it opens no inbound port), and gets the default pipe count.
func TestParseReverseOnlyForeign(t *testing.T) {
	cfg, err := parseConfig([]byte(`{
		"role": "foreign",
		"auth_token": "0123456789abcdef0123456789abcdef",
		"reverse_only": true,
		"reverse_targets": [{"target": "10.0.0.1:443", "mimic": "tls"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mimics) != 0 {
		t.Fatalf("reverse-only foreign must not synthesize listeners, got %+v", cfg.Mimics)
	}
	if cfg.ReverseConns != 12 {
		t.Fatalf("ReverseConns default = %d, want 12", cfg.ReverseConns)
	}
}

// Without reverse_only, a legacy foreign config still gets its SSH listener.
func TestParseForeignWithReverseKeepsListeners(t *testing.T) {
	cfg, err := parseConfig([]byte(`{
		"role": "foreign",
		"reverse_targets": [{"target": "10.0.0.1:443", "mimic": "tls"}],
		"reverse_conns": 20
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mimics) != 1 || cfg.Mimics[0].Type != "ssh" {
		t.Fatalf("expected the legacy ssh listener, got %+v", cfg.Mimics)
	}
	if cfg.ReverseConns != 20 {
		t.Fatalf("explicit ReverseConns must be kept, got %d", cfg.ReverseConns)
	}
}

// A reverse hub node has no endpoints to dial: none are synthesized from the legacy
// target fields, while its listeners and other defaults load normally.
func TestParseReverseNodeHasNoSynthesizedEndpoints(t *testing.T) {
	cfg, err := parseConfig([]byte(`{
		"role": "iran",
		"foreign_nodes": [{
			"alias": "n", "local_socks_port": 40001, "auth_token": "0123456789abcdef0123456789abcdef",
			"reverse": true,
			"reverse_listeners": [{"type": "tls", "port": 443}]
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.ForeignNodes[0]
	if len(n.Endpoints) != 0 {
		t.Fatalf("reverse node must not get a synthesized endpoint, got %+v", n.Endpoints)
	}
	if !n.Reverse || len(n.ReverseListeners) != 1 || n.ReverseListeners[0].Port != 443 {
		t.Fatalf("reverse fields lost: %+v", n)
	}
	if n.MinConnections != 10 || n.SocksBind != "127.0.0.1" {
		t.Fatalf("normal node defaults must still apply: %+v", n)
	}
}

// A node that is NOT reverse still gets its legacy SSH endpoint (unchanged behaviour).
func TestParseForwardNodeStillSynthesizesEndpoint(t *testing.T) {
	cfg, err := parseConfig([]byte(`{
		"role": "iran",
		"foreign_nodes": [{"alias": "n", "target_ip": "1.2.3.4", "local_socks_port": 40001, "auth_token": "0123456789abcdef0123456789abcdef"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	eps := cfg.ForeignNodes[0].Endpoints
	if len(eps) != 1 || eps[0].Target != "1.2.3.4:22" || eps[0].Mimic != "ssh" {
		t.Fatalf("legacy endpoint changed: %+v", eps)
	}
}
