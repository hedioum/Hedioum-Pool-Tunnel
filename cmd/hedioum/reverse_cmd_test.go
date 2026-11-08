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
