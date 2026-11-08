package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/persona"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

// Reverse tunnel switch. These two commands flip the connection direction of an
// EXISTING hub node / foreign pair without touching anything else: the token, SOCKS
// port, TUN/gateway settings, mimic set and bandwidth profile all stay as they are.
// In reverse mode the foreign dials the hub (useful when hub->foreign handshakes are
// filtered but foreign->hub works); the hub still opens every stream.

// reverseCapableTypes returns the node's mimic types usable for reverse listeners:
// SSH is excluded (it needs a real sshd decoy on the hub, and port 22 is normally
// taken there), everything else is a TLS/STARTTLS mimic that works on any host.
func reverseCapableTypes(types []string) []string {
	var out []string
	for _, t := range types {
		if t != "ssh" && validMimicType(t) {
			out = append(out, t)
		}
	}
	return out
}

// parsePortOverrides parses "tls=443,https-alt=8443" into a type->port map.
func parsePortOverrides(spec string) (map[string]int, error) {
	out := map[string]int{}
	if strings.TrimSpace(spec) == "" {
		return out, nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("%q is not TYPE=PORT", part)
		}
		ty := strings.TrimSpace(kv[0])
		if !validMimicType(ty) || ty == "ssh" {
			return nil, fmt.Errorf("%q is not a reverse-capable mimic type", ty)
		}
		p, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid port in %q", part)
		}
		if err := validPort(p); err != nil {
			return nil, err
		}
		out[ty] = p
	}
	return out, nil
}

// reverseFirewallPorts lists the public ports a hub must open for its reverse nodes.
func reverseFirewallPorts(cfg *config.AppConfig) []int {
	seen := map[int]bool{}
	var ports []int
	for _, n := range cfg.ForeignNodes {
		if !n.Reverse {
			continue
		}
		for _, ml := range n.ReverseListeners {
			if ml.Port != 0 && !seen[ml.Port] {
				seen[ml.Port] = true
				ports = append(ports, ml.Port)
			}
		}
	}
	sort.Ints(ports)
	return ports
}

// cmdReverseIran flips an existing hub node to reverse mode (or back with --forward)
// and prints the reverse pairing token the foreign needs.
func cmdReverseIran(args []string) {
	fs := flag.NewFlagSet("reverse-iran", flag.ExitOnError)
	alias := fs.String("alias", "", "node alias to flip (required)")
	portsSpec := fs.String("ports", "", "listener ports as TYPE=PORT,... (default: the node's current endpoint ports)")
	publicIP := fs.String("public-ip", "", "this hub's public IP to embed in the token (auto-detected if empty)")
	forward := fs.Bool("forward", false, "flip the node back to the normal mode (the hub dials the foreign)")
	_ = fs.Parse(args)

	if *alias == "" {
		fail("--alias is required")
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "iran" {
		fail("no Iran hub config (run this on the hub)")
	}
	var node *config.ForeignNode
	for i := range cfg.ForeignNodes {
		if cfg.ForeignNodes[i].Alias == *alias {
			node = &cfg.ForeignNodes[i]
			break
		}
	}
	if node == nil {
		fail("no node with alias %q", *alias)
	}

	if *forward {
		if !node.Reverse {
			fail("node %q is already in the normal (hub-dials-foreign) mode", *alias)
		}
		if len(node.Endpoints) == 0 {
			fail("node %q has no endpoints to dial; re-add it with add-node", *alias)
		}
		node.Reverse = false
		node.ReverseListeners = nil
		if err := config.SaveConfig(cfg); err != nil {
			fail("failed to save config: %v", err)
		}
		color.Green("[✓] Node %q is back to the normal mode (the hub dials the foreign).", *alias)
		color.Yellow("    Also run on the foreign: hedioum-tunnel reverse-foreign --forward")
		reconcileUnit("iran")
		restartDaemon()
		return
	}

	// Mimic set: the node's own (so both ends keep the same camouflage), minus SSH. A
	// legacy SSH-only node falls back to the token's persona.
	var types []string
	for _, e := range node.Endpoints {
		types = append(types, e.Mimic)
	}
	types = reverseCapableTypes(types)
	if len(types) == 0 {
		resolved, rerr := persona.Resolve(persona.Auto(node.AuthToken), node.AuthToken)
		if rerr != nil {
			fail("cannot derive a reverse mimic set: %v", rerr)
		}
		types = reverseCapableTypes(resolved)
	}

	overrides, err := parsePortOverrides(*portsSpec)
	if err != nil {
		fail("--ports: %v", err)
	}
	ports := currentNodePorts(*node)
	for ty, p := range overrides {
		ports[ty] = p
	}
	sni := firstEndpointSNI(*node)

	usedByOthers := map[int]string{}
	for _, n := range cfg.ForeignNodes {
		if n.Alias == node.Alias || !n.Reverse {
			continue
		}
		for _, ml := range n.ReverseListeners {
			usedByOthers[ml.Port] = n.Alias
		}
	}
	seen := map[int]string{}
	var listeners []config.MimicListener
	eps := map[string]int{}
	for _, ty := range types {
		p := ports[ty]
		if err := validPort(p); err != nil {
			fail("--ports %s: %v", ty, err)
		}
		if other, ok := seen[p]; ok {
			fail("port %d is used by both %s and %s; pass --ports to separate them", p, other, ty)
		}
		if other, ok := usedByOthers[p]; ok {
			fail("port %d is already used by reverse node %q; pass --ports to pick another", p, other)
		}
		seen[p] = ty
		listeners = append(listeners, config.MimicListener{Type: ty, Port: p, ServerName: sni})
		eps[ty] = p
	}

	ip := *publicIP
	if ip == "" {
		if detected, derr := sysutil.GetPublicIPv4(); derr == nil {
			ip = detected
		}
	}
	if ip == "" {
		fail("could not detect this hub's public IP; pass --public-ip")
	}
	if err := validIP(ip); err != nil {
		fail("--public-ip: %v", err)
	}

	node.Reverse = true
	node.ReverseListeners = listeners
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}

	typeNames := make([]string, len(listeners))
	for i, l := range listeners {
		typeNames[i] = fmt.Sprintf("%s:%d", l.Type, l.Port)
	}
	color.Green("[✓] Node %q is now in REVERSE mode (the foreign dials this hub).", *alias)
	color.Green("    Listening on: %s", strings.Join(typeNames, ", "))
	color.Yellow("    These ports must be reachable from the foreign server (open them in any")
	color.Yellow("    provider/network firewall; the host firewall is handled on start).")

	tok := pairing.Encode(pairing.Token{ExitIP: ip, AuthKey: node.AuthToken, SNI: sni, Endpoints: eps, Reverse: true})
	color.HiGreen("\n━━━ Foreign onboarding ━━━")
	color.HiGreen("Run this on the foreign server (same token/auth as before; only the direction flips):")
	fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)

	reconcileUnit("iran")
	restartDaemon()
}

// cmdReverseForeign makes an existing foreign dial out to the hub (or back with
// --forward). The foreign keeps its token and camouflage config.
func cmdReverseForeign(args []string) {
	fs := flag.NewFlagSet("reverse-foreign", flag.ExitOnError)
	token := fs.String("token", "", "reverse pairing token printed by `reverse-iran` on the hub")
	conns := fs.Int("conns", 0, "pipes to keep open to the hub (default 12; raise for more throughput)")
	keep := fs.Bool("keep-listeners", false, "also keep the normal inbound listeners (default: dial-out only, no open ports)")
	forward := fs.Bool("forward", false, "restore the normal mode (the hub dials this foreign)")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config (run this on the foreign; setup-foreign first)")
	}

	if *forward {
		if len(cfg.ReverseTargets) == 0 && !cfg.ReverseOnly {
			fail("this foreign is already in the normal (hub-dials-foreign) mode")
		}
		cfg.ReverseTargets = nil
		cfg.ReverseConns = 0
		cfg.ReverseOnly = false
		if err := config.SaveConfig(cfg); err != nil {
			fail("failed to save config: %v", err)
		}
		color.Green("[✓] Back to the normal mode: this foreign listens for the hub again.")
		color.Yellow("    Also run on the hub: hedioum-tunnel reverse-iran --alias NAME --forward")
		reconcileUnit("foreign")
		restartDaemon()
		return
	}

	if *token == "" {
		fail("--token is required (the reverse pairing token printed by `reverse-iran`)")
	}
	pt, isV2, perr := pairing.Decode(*token)
	if perr != nil || !isV2 {
		fail("--token must be a reverse pairing token from `reverse-iran` (%v)", perr)
	}
	if !pt.Reverse {
		fail("this is a normal pairing token; get a reverse one by running `reverse-iran` on the hub")
	}
	if *conns < 0 {
		fail("--conns must be positive")
	}

	var targets []config.Endpoint
	for _, ty := range mimicTypesAll {
		port, ok := pt.Endpoints[ty]
		if !ok || ty == "ssh" {
			continue
		}
		targets = append(targets, config.Endpoint{
			Target:     net.JoinHostPort(pt.ExitIP, strconv.Itoa(port)),
			Mimic:      ty,
			ServerName: pt.SNI,
		})
	}
	if len(targets) == 0 {
		fail("the token has no usable reverse endpoints")
	}

	if pt.AuthKey != cfg.AuthToken {
		color.Yellow("[!] The token's auth key differs from this foreign's: switching to the hub's key.")
		cfg.AuthToken = pt.AuthKey
	}
	cfg.ReverseTargets = targets
	cfg.ReverseConns = *conns // 0 = default (applied on load)
	cfg.ReverseOnly = !*keep
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}

	mode := "dial-out only (no inbound ports)"
	if *keep {
		mode = "dial-out plus the normal inbound listeners"
	}
	color.Green("[✓] Reverse mode on: dialing the hub across %d endpoint(s), %s.", len(targets), mode)
	reconcileUnit("foreign")
	restartDaemon()
}
