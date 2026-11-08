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

// reversePortCandidates are tried, in order, when the port a reverse listener would
// normally use is already taken on the hub (a panel, a web server, user configs...).
var reversePortCandidates = []int{8443, 2053, 2096, 2083, 2087, 9443, 4443, 10443, 8888}

// portInUse reports whether a TCP port cannot be bound on this host. A variable so
// tests can fake it.
var portInUse = func(p int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return true
	}
	_ = l.Close()
	return false
}

// reversePlan is what flipping a node to reverse mode will do.
type reversePlan struct {
	Listeners []config.MimicListener
	Endpoints map[string]int // type -> port, as embedded in the pairing token
	SNI       string
	Moved     map[string]int // type -> port it would normally use but was taken (auto-moved)
}

func findNode(cfg *config.AppConfig, alias string) *config.ForeignNode {
	for i := range cfg.ForeignNodes {
		if cfg.ForeignNodes[i].Alias == alias {
			return &cfg.ForeignNodes[i]
		}
	}
	return nil
}

// planReverse works out the reverse listeners for a node: its own mimic set minus
// SSH, each on the node's current port unless the operator overrode it. A port that
// is taken on this host (or by another reverse node) is moved to a free candidate
// automatically; an explicit override that is taken is an error.
func planReverse(cfg *config.AppConfig, node *config.ForeignNode, overrides map[string]int, sni string) (reversePlan, error) {
	return planReverseFor(cfg, node, overrides, sni, false)
}

// planReverseFor is planReverse with the choice of listener set. By default a node that
// is flipped to reverse gets ONE listener, the TLS mimic (normally on 443, behind a front
// proxy if the port is shared): every extra public listener on the hub is one more port
// to probe, and in reverse mode only a TLS-type pipe is useful anyway (SSH cannot be
// used). Extra types are opt-in: naming them in --ports, or
// all of the node's own set with allTypes (--all-mimics). A node that is already reverse
// keeps the types it has.
func planReverseFor(cfg *config.AppConfig, node *config.ForeignNode, overrides map[string]int, sni string, allTypes bool) (reversePlan, error) {
	var nodeTypes []string
	for _, e := range node.Endpoints {
		nodeTypes = append(nodeTypes, e.Mimic)
	}
	nodeTypes = reverseCapableTypes(nodeTypes)
	if len(nodeTypes) == 0 {
		resolved, err := persona.Resolve(persona.Auto(node.AuthToken), node.AuthToken)
		if err != nil {
			return reversePlan{}, fmt.Errorf("cannot derive a reverse mimic set: %v", err)
		}
		nodeTypes = reverseCapableTypes(resolved)
	}
	var types []string
	switch {
	case allTypes:
		types = nodeTypes
	case node.Reverse && len(node.ReverseListeners) > 0:
		for _, l := range node.ReverseListeners {
			types = append(types, l.Type)
		}
	default:
		types = []string{"tls"}
	}
	have := map[string]bool{}
	for _, ty := range types {
		have[ty] = true
	}
	extra := make([]string, 0, len(overrides))
	for ty := range overrides {
		if !have[ty] {
			extra = append(extra, ty)
		}
	}
	sort.Strings(extra)
	types = append(types, extra...)

	ports := currentNodePorts(*node)
	usedByOthers := map[int]string{}
	for _, n := range cfg.ForeignNodes {
		if n.Alias == node.Alias || !n.Reverse {
			continue
		}
		for _, ml := range n.ReverseListeners {
			usedByOthers[ml.Port] = n.Alias
		}
	}
	// Ports this node's own (already running) reverse listeners hold are not "taken".
	own := map[int]bool{}
	if node.Reverse {
		for _, ml := range node.ReverseListeners {
			own[ml.Port] = true
		}
	}
	taken := func(p int, inPlan map[int]string) bool {
		if _, ok := usedByOthers[p]; ok {
			return true
		}
		if _, ok := inPlan[p]; ok {
			return true
		}
		return !own[p] && portInUse(p)
	}

	if sni == "" {
		sni = firstEndpointSNI(*node)
	}
	plan := reversePlan{Endpoints: map[string]int{}, Moved: map[string]int{}, SNI: sni}
	inPlan := map[int]string{}
	chosen := map[string]int{}

	// Pass 1: explicit overrides and every type whose usual port is free keep it, so a
	// type that has to move can never grab a port another type is about to keep.
	var needMove []string
	for _, ty := range types {
		if p, explicit := overrides[ty]; explicit {
			if err := validPort(p); err != nil {
				return reversePlan{}, fmt.Errorf("--ports %s: %v", ty, err)
			}
			if other, ok := inPlan[p]; ok {
				return reversePlan{}, fmt.Errorf("port %d is used by both %s and %s; pass --ports to separate them", p, other, ty)
			}
			if other, ok := usedByOthers[p]; ok {
				return reversePlan{}, fmt.Errorf("port %d is already used by reverse node %q; pass --ports to pick another", p, other)
			}
			if !own[p] && portInUse(p) {
				return reversePlan{}, fmt.Errorf("port %d (%s) is already in use on this host; pick another", p, ty)
			}
			inPlan[p], chosen[ty] = ty, p
			continue
		}
		if p := ports[ty]; p > 0 && !taken(p, inPlan) {
			inPlan[p], chosen[ty] = ty, p
			continue
		}
		needMove = append(needMove, ty)
	}
	// Pass 2: move the rest to the first free candidate.
	for _, ty := range needMove {
		p := 0
		for _, c := range reversePortCandidates {
			if !taken(c, inPlan) {
				p = c
				break
			}
		}
		if p == 0 {
			return reversePlan{}, fmt.Errorf("no free port found for %s; pass --ports", ty)
		}
		if old := ports[ty]; old > 0 {
			plan.Moved[ty] = old
		}
		inPlan[p], chosen[ty] = ty, p
	}
	for _, ty := range types {
		p := chosen[ty]
		plan.Listeners = append(plan.Listeners, config.MimicListener{Type: ty, Port: p, ServerName: plan.SNI})
		plan.Endpoints[ty] = p
	}
	return plan, nil
}

// resolveHubIP returns the hub's public IP: the given one, or auto-detected.
func resolveHubIP(given string) (string, error) {
	ip := given
	if ip == "" {
		if detected, err := sysutil.GetPublicIPv4(); err == nil {
			ip = detected
		}
	}
	if ip == "" {
		return "", fmt.Errorf("could not detect this hub's public IP; pass --public-ip")
	}
	if err := validIP(ip); err != nil {
		return "", fmt.Errorf("--public-ip: %v", err)
	}
	return ip, nil
}

// reverseOpts are the camouflage settings of a reverse node that the operator can set
// to mirror what the foreign wears. Empty values keep the node's current ones.
type reverseOpts struct {
	SNI   string // TLS SNI the foreign sends and the hub's certificate is issued for
	Decoy string // decoy persona for unauthorized probes: apache | directadmin
	// AllTypes opens a listener for every mimic type of the node instead of the TLS one.
	AllTypes bool
	// Advertise overrides the port the foreign is told to dial for a mimic type, when it
	// differs from the port the hub listens on (e.g. a front proxy owns :443 and forwards
	// by SNI to the listener). Only the token changes; the listeners stay as planned.
	Advertise map[string]int
}

func validDecoyStyle(s string) error {
	if s == "" || s == "apache" || s == "directadmin" {
		return nil
	}
	return fmt.Errorf("decoy style must be apache or directadmin")
}

// applyReverseIran flips the node to reverse mode in cfg (the caller saves it) and
// returns the plan plus the reverse pairing token for the foreign.
func applyReverseIran(cfg *config.AppConfig, alias string, overrides map[string]int, publicIP string, opts reverseOpts) (reversePlan, string, error) {
	node := findNode(cfg, alias)
	if node == nil {
		return reversePlan{}, "", fmt.Errorf("no node with alias %q", alias)
	}
	if err := validDecoyStyle(opts.Decoy); err != nil {
		return reversePlan{}, "", err
	}
	plan, err := planReverseFor(cfg, node, overrides, opts.SNI, opts.AllTypes)
	if err != nil {
		return reversePlan{}, "", err
	}
	ip, err := resolveHubIP(publicIP)
	if err != nil {
		return reversePlan{}, "", err
	}
	advertised := map[string]int{}
	for ty, p := range plan.Endpoints {
		advertised[ty] = p
	}
	for ty, p := range opts.Advertise {
		if _, ok := plan.Endpoints[ty]; !ok {
			return reversePlan{}, "", fmt.Errorf("--advertise-ports %s: the node has no reverse listener of that type", ty)
		}
		if err := validPort(p); err != nil {
			return reversePlan{}, "", fmt.Errorf("--advertise-ports %s: %v", ty, err)
		}
		advertised[ty] = p
	}
	node.Reverse = true
	node.ReverseListeners = plan.Listeners
	if opts.Decoy != "" {
		node.ReverseDecoyStyle = opts.Decoy
	}
	tok := pairing.Encode(pairing.Token{ExitIP: ip, AuthKey: node.AuthToken, SNI: plan.SNI, Endpoints: advertised, Reverse: true})
	return plan, tok, nil
}

// applyForwardIran flips a reverse node back to the normal mode in cfg.
func applyForwardIran(cfg *config.AppConfig, alias string) error {
	node := findNode(cfg, alias)
	if node == nil {
		return fmt.Errorf("no node with alias %q", alias)
	}
	if !node.Reverse {
		return fmt.Errorf("node %q is already in the normal (hub-dials-foreign) mode", alias)
	}
	if len(node.Endpoints) == 0 {
		return fmt.Errorf("node %q has no endpoints to dial; re-add it with add-node", alias)
	}
	node.Reverse = false
	node.ReverseListeners = nil
	node.ReverseDecoyStyle = ""
	return nil
}

// applyReverseForeign switches a foreign config to dial the hub from a reverse
// pairing token. It returns the number of endpoints and whether the auth key changed.
func applyReverseForeign(cfg *config.AppConfig, token string, conns int, keep bool) (int, bool, error) {
	pt, isV2, err := pairing.Decode(token)
	if err != nil || !isV2 {
		return 0, false, fmt.Errorf("the token must be a reverse pairing token from `reverse-iran` (%v)", err)
	}
	if !pt.Reverse {
		return 0, false, fmt.Errorf("this is a normal pairing token; get a reverse one by running `reverse-iran` on the hub")
	}
	if conns < 0 {
		return 0, false, fmt.Errorf("--conns must be positive")
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
		return 0, false, fmt.Errorf("the token has no usable reverse endpoints")
	}
	keyChanged := pt.AuthKey != cfg.AuthToken
	if keyChanged {
		cfg.AuthToken = pt.AuthKey
	}
	cfg.ReverseTargets = targets
	cfg.ReverseConns = conns // 0 = default (applied on load)
	cfg.ReverseOnly = !keep
	return len(targets), keyChanged, nil
}

// applyForwardForeign restores the normal mode on a foreign config.
func applyForwardForeign(cfg *config.AppConfig) error {
	if len(cfg.ReverseTargets) == 0 && !cfg.ReverseOnly {
		return fmt.Errorf("this foreign is already in the normal (hub-dials-foreign) mode")
	}
	cfg.ReverseTargets = nil
	cfg.ReverseConns = 0
	cfg.ReverseOnly = false
	return nil
}

// printReversePlan prints the listeners (and any auto-moved ports) of a plan.
func printReversePlan(alias string, plan reversePlan) {
	names := make([]string, len(plan.Listeners))
	for i, l := range plan.Listeners {
		names[i] = fmt.Sprintf("%s:%d", l.Type, l.Port)
	}
	color.Green("[✓] Node %q is now in REVERSE mode (the foreign dials this hub).", alias)
	color.Green("    Listening on: %s", strings.Join(names, ", "))
	for _, l := range plan.Listeners {
		if old, moved := plan.Moved[l.Type]; moved {
			color.Yellow("    %s: port %d is taken on this host, using %d instead.", l.Type, old, l.Port)
		}
	}
	if plan.SNI != "" {
		color.Green("    SNI: %s", plan.SNI)
	}
	color.Yellow("    These ports must be reachable from the foreign server (open them in any")
	color.Yellow("    provider/network firewall; the host firewall is handled on start).")
}

// cmdReverseIran flips an existing hub node to reverse mode (or back with --forward)
// and prints the reverse pairing token the foreign needs.
func cmdReverseIran(args []string) {
	fs := flag.NewFlagSet("reverse-iran", flag.ExitOnError)
	alias := fs.String("alias", "", "node alias to flip (required)")
	portsSpec := fs.String("ports", "", "listener ports as TYPE=PORT,... (default: the node's endpoint ports; a port taken on this host is replaced by a free one)")
	publicIP := fs.String("public-ip", "", "this hub's public IP to embed in the token (auto-detected if empty)")
	sni := fs.String("sni", "", "TLS SNI the foreign sends and the hub's certificate is issued for (default: the node's current SNI)")
	advertise := fs.String("advertise-ports", "", "ports the foreign dials, as TYPE=PORT,... when a front proxy (nginx stream) forwards them to the listener ports")
	decoy := fs.String("decoy-style", "", "decoy shown to unauthorized probes: apache|directadmin (default: the node's, else the hub's)")
	allMimics := fs.Bool("all-mimics", false, "open a listener for every mimic type of the node (default: one TLS listener; name extra types in --ports)")
	forward := fs.Bool("forward", false, "flip the node back to the normal mode (the hub dials the foreign)")
	_ = fs.Parse(args)

	if *alias == "" {
		fail("--alias is required")
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "iran" {
		fail("no Iran hub config (run this on the hub)")
	}

	if *forward {
		if err := applyForwardIran(cfg, *alias); err != nil {
			fail("%v", err)
		}
		if err := config.SaveConfig(cfg); err != nil {
			fail("failed to save config: %v", err)
		}
		color.Green("[✓] Node %q is back to the normal mode (the hub dials the foreign).", *alias)
		color.Yellow("    Also run on the foreign: hedioum-tunnel reverse-foreign --forward")
		reconcileUnit("iran")
		restartDaemon()
		return
	}

	overrides, err := parsePortOverrides(*portsSpec)
	if err != nil {
		fail("--ports: %v", err)
	}
	adv, err := parsePortOverrides(*advertise)
	if err != nil {
		fail("--advertise-ports: %v", err)
	}
	plan, tok, err := applyReverseIran(cfg, *alias, overrides, *publicIP, reverseOpts{SNI: *sni, Decoy: *decoy, Advertise: adv, AllTypes: *allMimics})
	if err != nil {
		fail("%v", err)
	}
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	printReversePlan(*alias, plan)
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
		if err := applyForwardForeign(cfg); err != nil {
			fail("%v", err)
		}
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
	n, keyChanged, err := applyReverseForeign(cfg, *token, *conns, *keep)
	if err != nil {
		fail("%v", err)
	}
	if keyChanged {
		color.Yellow("[!] The token's auth key differs from this foreign's: switched to the hub's key.")
	}
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	mode := "dial-out only (no inbound ports)"
	if *keep {
		mode = "dial-out plus the normal inbound listeners"
	}
	color.Green("[✓] Reverse mode on: dialing the hub across %d endpoint(s), %s.", n, mode)
	reconcileUnit("foreign")
	restartDaemon()
}
