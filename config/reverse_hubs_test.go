package config

import "testing"

func TestEffectiveReverseHubsLegacyAndDefaults(t *testing.T) {
	// A config written before reverse_hubs existed is one hub named "default".
	cfg, err := parseConfig([]byte(`{"role":"foreign","auth_token":"tok","reverse_only":true,
		"reverse_targets":[{"target":"1.2.3.4:443","mimic":"tls"}],"reverse_conns":8}`))
	if err != nil {
		t.Fatal(err)
	}
	hubs := cfg.EffectiveReverseHubs()
	if len(hubs) != 1 || hubs[0].Name != "default" || hubs[0].MinConns != 8 || hubs[0].MaxConns != 8 || hubs[0].AuthToken != "tok" {
		t.Fatalf("legacy hub wrong: %+v", hubs)
	}

	// No reverse fields at all: nothing to dial.
	cfg, _ = parseConfig([]byte(`{"role":"foreign","auth_token":"tok"}`))
	if got := cfg.EffectiveReverseHubs(); len(got) != 0 {
		t.Fatalf("a normal foreign has no hubs, got %+v", got)
	}

	// Defaults: min 12, max follows min, a smaller max is raised, own token inherited.
	cfg = &AppConfig{AuthToken: "own", ReverseHubs: []ReverseHub{
		{Name: "a", Targets: []Endpoint{{Target: "1.1.1.1:443", Mimic: "tls"}}},
		{Name: "b", Targets: []Endpoint{{Target: "2.2.2.2:443", Mimic: "tls"}}, MinConns: 5, MaxConns: 2, AuthToken: "other"},
	}}
	h := cfg.EffectiveReverseHubs()
	if h[0].MinConns != 12 || h[0].MaxConns != 12 || h[0].AuthToken != "own" {
		t.Fatalf("hub a defaults: %+v", h[0])
	}
	if h[1].MinConns != 5 || h[1].MaxConns != 5 || h[1].AuthToken != "other" {
		t.Fatalf("hub b defaults: %+v", h[1])
	}
}

// Older binaries only know reverse_targets/reverse_conns, so they are kept as the union
// of the hubs' targets and the sum of their minimums.
func TestSyncReverseCompat(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"role":"foreign","auth_token":"tok","reverse_only":true,"reverse_hubs":[
		{"name":"a","targets":[{"target":"1.1.1.1:443","mimic":"tls"}],"min_conns":3,"max_conns":6},
		{"name":"b","targets":[{"target":"1.1.1.1:443","mimic":"tls"},{"target":"2.2.2.2:8443","mimic":"https-alt"}],"min_conns":4}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReverseConns != 7 || len(cfg.ReverseTargets) != 2 {
		t.Fatalf("compat fields wrong: conns=%d targets=%+v", cfg.ReverseConns, cfg.ReverseTargets)
	}
}

// The menus propose the usual 10 to 20 style range, never a maximum below the minimum.
func TestSuggestedReverseMaxFor(t *testing.T) {
	if got := SuggestedReverseMaxFor(DefaultReverseConns); got != SuggestedReverseMax {
		t.Fatalf("default minimum: got %d, want %d", got, SuggestedReverseMax)
	}
	if got := SuggestedReverseMaxFor(30); got != 30 {
		t.Fatalf("a minimum above the suggestion must not be lowered: got %d", got)
	}
}

func TestNormalizeEgressUpstream(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "",
		"127.0.0.1:10808":            "127.0.0.1:10808",
		" socks5://127.0.0.1:10808 ": "127.0.0.1:10808",
		"[::1]:1080":                 "[::1]:1080",
	} {
		if got, err := NormalizeEgressUpstream(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"10808", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", ":1080", "http://x:1"} {
		if _, err := NormalizeEgressUpstream(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
