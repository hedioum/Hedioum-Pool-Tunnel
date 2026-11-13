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
		if !n.Reverse || isLoopbackBind(n.ReverseBind) {
			continue // not reachable from outside: nothing to open (a front proxy owns the public port)
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
	Listeners  []config.MimicListener
	Endpoints  map[string]int // type -> port, as embedded in the pairing token
	SNI        string
	Moved      map[string]int // type -> port it would normally use but was taken (auto-moved)
	Advertised map[string]int // type -> port the foreign is told to dial (differs behind a front proxy)
	Warnings   []string
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
	case len(node.ReverseListeners) > 0:
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
	for _, l := range node.ReverseListeners { // remembered listener ports win over the endpoint ports
		ports[l.Type] = l.Port
	}
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

	if sni == "" && len(node.ReverseListeners) > 0 {
		sni = node.ReverseListeners[0].ServerName
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

// reverseOpts are the camouflage and front-proxy settings of a reverse node that the
// operator can set. Zero values keep the node's current ones.
type reverseOpts struct {
	SNI   string // TLS SNI the foreign sends and the hub's certificate is issued for
	Decoy string // decoy persona for unauthorized probes: apache | directadmin
	// AllTypes opens a listener for every mimic type of the node instead of the TLS one.
	AllTypes bool
	// Advertise overrides the port the foreign is told to dial for a mimic type, when it
	// differs from the port the hub listens on (a front proxy owns :443 and forwards by
	// SNI to the listener). Only advertised types get a listener and a token endpoint,
	// since one SNI can be routed to one listener. AdvertiseSet distinguishes "not
	// given" (keep the node's) from "given empty" (clear).
	Advertise    map[string]int
	AdvertiseSet bool
	// Bind is the listener bind address ("127.0.0.1" behind a front proxy); nil keeps
	// the node's. ProxyProtocol requires a PROXY header from the front proxy; nil keeps.
	Bind          *string
	ProxyProtocol *bool
	// ShareWith joins another reverse node's listener (same port, type, SNI, bind and
	// front-proxy settings), so one SNI carries several foreign servers. It needs the
	// advanced shared_reverse_auth setting; the hub then tells the nodes apart by token.
	ShareWith string
	// MinPipes / MaxPipes set the node's pipe range (0 keeps it). The range is also put
	// in the pairing token, so the foreign opens that many pipes without being told.
	MinPipes, MaxPipes int
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
	var plan reversePlan
	adv := node.ReverseAdvertise
	if opts.ShareWith != "" {
		src, err := shareSource(cfg, node, opts)
		if err != nil {
			return reversePlan{}, "", err
		}
		plan = reversePlan{Endpoints: map[string]int{}, Moved: map[string]int{}}
		for _, l := range src.ReverseListeners {
			plan.Listeners = append(plan.Listeners, l)
			plan.Endpoints[l.Type] = l.Port
			plan.SNI = l.ServerName
		}
		adv = src.ReverseAdvertise
		node.ReverseShareWith = src.Alias
		// The sharing node must run on the same socket settings as the one it joins.
		bind, proxy := src.ReverseBind, src.ReverseProxyProtocol
		opts.Bind, opts.ProxyProtocol = &bind, &proxy
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("this node shares the listener of %q: the hub tells the two foreign servers apart by token", src.Alias))
	} else {
		var err error
		node.ReverseShareWith = ""
		plan, err = planReverseFor(cfg, node, overrides, opts.SNI, opts.AllTypes)
		if err != nil {
			return reversePlan{}, "", err
		}
		if opts.AdvertiseSet {
			adv = opts.Advertise
		}
	}
	ip, err := resolveHubIP(publicIP)
	if err != nil {
		return reversePlan{}, "", err
	}
	if opts.Bind != nil {
		if err := validBind(*opts.Bind); err != nil {
			return reversePlan{}, "", fmt.Errorf("--bind: %v", err)
		}
	}

	advertised := map[string]int{}
	if len(adv) == 0 {
		for ty, p := range plan.Endpoints {
			advertised[ty] = p
		}
	} else {
		// Front-proxy mode: only the advertised types are served, each on its own public
		// port (a front proxy routes one SNI to one listener).
		seenPort := map[int]string{}
		var keep []config.MimicListener
		for _, l := range plan.Listeners {
			p, ok := adv[l.Type]
			if !ok {
				continue
			}
			if err := validPort(p); err != nil {
				return reversePlan{}, "", fmt.Errorf("--advertise-ports %s: %v", l.Type, err)
			}
			if other, dup := seenPort[p]; dup {
				return reversePlan{}, "", fmt.Errorf("--advertise-ports: %s and %s both use port %d, but a front proxy routes one SNI to one listener; advertise a single type per port", other, l.Type, p)
			}
			seenPort[p] = l.Type
			keep = append(keep, l)
			advertised[l.Type] = p
		}
		for ty := range adv {
			if _, ok := plan.Endpoints[ty]; !ok {
				return reversePlan{}, "", fmt.Errorf("--advertise-ports %s: the node has no reverse listener of that type", ty)
			}
		}
		plan.Listeners = keep
		eps := map[string]int{}
		for _, l := range keep {
			eps[l.Type] = l.Port
		}
		plan.Endpoints = eps
	}
	plan.Advertised = advertised

	node.Reverse = true
	node.ReverseListeners = plan.Listeners
	if opts.Decoy != "" {
		node.ReverseDecoyStyle = opts.Decoy
	}
	if opts.Bind != nil {
		node.ReverseBind = *opts.Bind
	}
	if opts.ProxyProtocol != nil {
		node.ReverseProxyProtocol = *opts.ProxyProtocol
	}
	if len(adv) == 0 {
		node.ReverseAdvertise = nil
	} else {
		node.ReverseAdvertise = map[string]int{}
		for ty, p := range advertised {
			node.ReverseAdvertise[ty] = p
		}
	}
	if node.ReverseProxyProtocol && !isLoopbackBind(node.ReverseBind) {
		plan.Warnings = append(plan.Warnings, "PROXY protocol is required but the listeners are not bound to a loopback address: anything reaching them directly is dropped, so also use --bind 127.0.0.1")
	}
	if len(adv) > 0 && !isLoopbackBind(node.ReverseBind) {
		plan.Warnings = append(plan.Warnings, "a front proxy is in use but the listeners are still reachable directly; --bind 127.0.0.1 keeps them behind the proxy")
	}
	if opts.MinPipes > 0 || opts.MaxPipes > 0 {
		min, max := opts.MinPipes, opts.MaxPipes
		if min == 0 {
			min = node.MinConnections
		}
		if max == 0 {
			max = node.MaxConnections
		}
		if min == 0 {
			min = config.DefaultReverseConns
		}
		if max == 0 || max < min {
			max = config.SuggestedReverseMaxFor(min)
		}
		if err := validPipeRange(min, max); err != nil {
			return reversePlan{}, "", fmt.Errorf("pipes: %v", err)
		}
		node.MinConnections, node.MaxConnections = min, max
	}
	pt := pairing.Token{ExitIP: ip, AuthKey: node.AuthToken, SNI: plan.SNI, Endpoints: advertised, Reverse: true}
	if node.MinConnections > 0 && node.MaxConnections >= node.MinConnections {
		pt.MinConns, pt.MaxConns = node.MinConnections, node.MaxConnections
	}
	tok := pairing.Encode(pt)
	return plan, tok, nil
}

// shareSource validates --share-with and returns the node whose listener is joined.
func shareSource(cfg *config.AppConfig, node *config.ForeignNode, opts reverseOpts) (*config.ForeignNode, error) {
	if !cfg.SharedReverseAuth {
		return nil, fmt.Errorf("sharing a listener is an advanced setting that is off; turn it on first: hedioum-tunnel reverse-shared-auth --on")
	}
	src := findNode(cfg, opts.ShareWith)
	switch {
	case src == nil:
		return nil, fmt.Errorf("--share-with: no node with alias %q", opts.ShareWith)
	case src.Alias == node.Alias:
		return nil, fmt.Errorf("--share-with: a node cannot share its own listener")
	case !src.Reverse || len(src.ReverseListeners) == 0:
		return nil, fmt.Errorf("--share-with: node %q is not in reverse mode", src.Alias)
	case opts.SNI != "" && opts.SNI != src.ReverseListeners[0].ServerName:
		return nil, fmt.Errorf("--share-with: the SNI is %q on %q; a shared listener has one SNI", src.ReverseListeners[0].ServerName, src.Alias)
	}
	for _, l := range src.ReverseListeners {
		if l.Type == "ssh" {
			return nil, fmt.Errorf("--share-with: the ssh mimic cannot share a listener")
		}
	}
	return src, nil
}

// sharedGroups lists the reverse nodes that currently share a listener, as
// "listener: alias, alias" lines (empty when none do).
func sharedGroups(cfg *config.AppConfig) []string {
	byAddr := map[string][]string{}
	var order []string
	for _, n := range cfg.ForeignNodes {
		if !n.Reverse {
			continue
		}
		for _, l := range n.ReverseListeners {
			key := fmt.Sprintf("%s:%d", n.ReverseBind, l.Port)
			if _, ok := byAddr[key]; !ok {
				order = append(order, key)
			}
			byAddr[key] = append(byAddr[key], n.Alias)
		}
	}
	var out []string
	for _, k := range order {
		if len(byAddr[k]) > 1 {
			out = append(out, fmt.Sprintf("%s: %s", k, strings.Join(byAddr[k], ", ")))
		}
	}
	return out
}

// setSharedReverseAuth turns the advanced shared-listener setting on or off. It can
// only be turned off once no two nodes use the same listener any more.
func setSharedReverseAuth(cfg *config.AppConfig, on bool) error {
	if !on {
		if groups := sharedGroups(cfg); len(groups) > 0 {
			return fmt.Errorf("these listeners are shared and would stop working; give each node its own port first (reverse-iran --alias NAME --ports ...): %s", strings.Join(groups, "; "))
		}
	}
	cfg.SharedReverseAuth = on
	return nil
}

// cmdReverseSharedAuth shows or changes the advanced shared-listener setting.
func cmdReverseSharedAuth(args []string) {
	fs := flag.NewFlagSet("reverse-shared-auth", flag.ExitOnError)
	on := fs.Bool("on", false, "allow several reverse nodes to share one listener (one SNI, nodes told apart by token)")
	off := fs.Bool("off", false, "back to one listener per node (default)")
	_ = fs.Parse(args)
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "iran" {
		fail("no Iran hub config (run this on the hub)")
	}
	if *on && *off {
		fail("pass either --on or --off")
	}
	if !*on && !*off {
		state := "off"
		if cfg.SharedReverseAuth {
			state = "on"
		}
		fmt.Printf("Shared reverse listeners: %s\n", state)
		for _, g := range sharedGroups(cfg) {
			fmt.Printf("  shared: %s\n", g)
		}
		return
	}
	if err := setSharedReverseAuth(cfg, *on); err != nil {
		fail("%v", err)
	}
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	if *on {
		color.Green("[✓] Shared reverse listeners are on.")
		color.Yellow("    Join a node to another's listener with: hedioum-tunnel reverse-iran --alias NEW --share-with EXISTING")
	} else {
		color.Green("[✓] Shared reverse listeners are off (one listener per node).")
	}
	reconcileUnit("iran")
	restartDaemon()
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
	// Only the switch is cleared: listeners, bind, PROXY protocol, SNI and advertised
	// ports are remembered, so switching to reverse again needs no reconfiguration.
	node.Reverse = false
	return nil
}

// resumeShareWith returns the node whose listener a switched-back node joined before,
// if that node is still a reverse node and sharing is still allowed; else "".
func resumeShareWith(cfg *config.AppConfig, alias string) string {
	node := findNode(cfg, alias)
	if node == nil || node.ReverseShareWith == "" || !cfg.SharedReverseAuth {
		return ""
	}
	if src := findNode(cfg, node.ReverseShareWith); src == nil || !src.Reverse || len(src.ReverseListeners) == 0 {
		return ""
	}
	return node.ReverseShareWith
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
	if len(cfg.ReverseHubs) > 1 {
		return 0, false, fmt.Errorf("this foreign dials several hubs; manage them with add-hub / edit-hub / remove-hub (or `reverse-foreign --forward` to reset)")
	}
	targets := reverseTargetsFromToken(pt)
	if len(targets) == 0 {
		return 0, false, fmt.Errorf("the token has no usable reverse endpoints")
	}
	keyChanged := pt.AuthKey != cfg.AuthToken
	if keyChanged {
		cfg.AuthToken = pt.AuthKey
	}
	// The pipe count: --conns wins, else the range the hub put in the token, else 12.
	min, max := conns, conns
	if conns == 0 && pt.MinConns > 0 && validPipeRange(pt.MinConns, pt.MaxConns) == nil {
		min, max = pt.MinConns, pt.MaxConns
	}
	if len(cfg.ReverseHubs) == 1 || max > min {
		name := "default"
		if len(cfg.ReverseHubs) == 1 {
			cur := cfg.ReverseHubs[0]
			name = cur.Name
			if min == 0 {
				min, max = cur.MinConns, cur.MaxConns
			}
		}
		cfg.ReverseHubs = []config.ReverseHub{{Name: name, Targets: targets, MinConns: min, MaxConns: max}}
		cfg.SyncReverseCompat()
	} else {
		cfg.ReverseTargets = targets
		cfg.ReverseConns = conns // 0 = default (applied on load)
	}
	cfg.ReverseOnly = !keep
	cfg.ReverseSaved = nil
	return len(targets), keyChanged, nil
}

// reverseTargetsFromToken turns a reverse pairing token into the hub endpoints the
// foreign dials (SSH is never reverse-capable).
func reverseTargetsFromToken(pt *pairing.Token) []config.Endpoint {
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
	return targets
}

// applyForwardForeign restores the normal mode on a foreign config.
func applyForwardForeign(cfg *config.AppConfig) error {
	if len(cfg.ReverseTargets) == 0 && len(cfg.ReverseHubs) == 0 && !cfg.ReverseOnly {
		return fmt.Errorf("this foreign is already in the normal (hub-dials-foreign) mode")
	}
	cfg.ReverseSaved = &config.ReverseSaved{Hubs: cfg.ReverseHubs, Targets: cfg.ReverseTargets, Conns: cfg.ReverseConns, Only: cfg.ReverseOnly}
	cfg.ReverseHubs = nil
	cfg.ReverseTargets = nil
	cfg.ReverseConns = 0
	cfg.ReverseOnly = false
	return nil
}

// applyResumeForeign switches a foreign back to the reverse mode it had before
// applyForwardForeign, with the same hubs, pipes and listener choice: no token needed.
func applyResumeForeign(cfg *config.AppConfig) error {
	if len(cfg.ReverseTargets) > 0 || len(cfg.ReverseHubs) > 0 {
		return fmt.Errorf("this foreign is already in reverse mode")
	}
	s := cfg.ReverseSaved
	if s == nil || (len(s.Targets) == 0 && len(s.Hubs) == 0) {
		return fmt.Errorf("no saved reverse settings; use `reverse-foreign --token ...` with a token from the hub")
	}
	cfg.ReverseHubs = s.Hubs
	cfg.ReverseTargets = s.Targets
	cfg.ReverseConns = s.Conns
	cfg.ReverseOnly = s.Only
	cfg.ReverseSaved = nil
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
	for _, l := range plan.Listeners {
		if p, ok := plan.Advertised[l.Type]; ok && p != l.Port {
			color.Green("    %s: the foreign dials port %d (your front proxy forwards it to :%d)", l.Type, p, l.Port)
		}
	}
	for _, w := range plan.Warnings {
		color.Yellow("    [!] %s", w)
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
	advertise := fs.String("advertise-ports", "", "ports the foreign dials, as TYPE=PORT,... when a front proxy (nginx stream) forwards them to the listener ports (remembered; \"\" clears)")
	bind := fs.String("bind", "", "address the listeners bind to (127.0.0.1 behind a front proxy; \"\" = all interfaces; remembered)")
	proxyProto := fs.Bool("proxy-protocol", false, "require a PROXY protocol header from the front proxy (nginx proxy_protocol on / HAProxy send-proxy; remembered)")
	shareWith := fs.String("share-with", "", "advanced: join this reverse node's listener (same port/SNI) instead of getting its own; needs `reverse-shared-auth --on`")
	decoy := fs.String("decoy-style", "", "decoy shown to unauthorized probes: apache|directadmin (default: the node's, else the hub's)")
	allMimics := fs.Bool("all-mimics", false, "open a listener for every mimic type of the node (default: one TLS listener; name extra types in --ports)")
	minPipes := fs.Int("min-pipes", 0, "pipes the foreign always keeps open to this hub (put in the token; 0 = the node's range)")
	maxPipes := fs.Int("max-pipes", 0, "most pipes the foreign opens under load (put in the token; 0 = the node's range)")
	forward := fs.Bool("forward", false, "flip the node back to the normal mode (the hub dials the foreign); its reverse settings are remembered")
	resume := fs.Bool("resume", false, "flip the node back to reverse mode with the settings it had (ports, SNI, front proxy); no other flag needed")
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
		color.Yellow("    Its reverse settings are remembered: to switch back run reverse-iran --alias %s --resume", *alias)
		color.Yellow("    Also run on the foreign: hedioum-tunnel reverse-foreign --forward")
		reconcileUnit("iran")
		restartDaemon()
		return
	}

	if *resume {
		node := findNode(cfg, *alias)
		if node == nil {
			fail("no node with alias %q", *alias)
		}
		if node.Reverse {
			fail("node %q is already in reverse mode", *alias)
		}
		if len(node.ReverseListeners) == 0 {
			fail("node %q has no saved reverse settings; run reverse-iran --alias %s once without --resume", *alias, *alias)
		}
	}
	overrides, err := parsePortOverrides(*portsSpec)
	if err != nil {
		fail("--ports: %v", err)
	}
	adv, err := parsePortOverrides(*advertise)
	if err != nil {
		fail("--advertise-ports: %v", err)
	}
	opts := reverseOpts{SNI: *sni, Decoy: *decoy, Advertise: adv, ShareWith: *shareWith, AllTypes: *allMimics, MinPipes: *minPipes, MaxPipes: *maxPipes}
	if *resume {
		opts.ShareWith = resumeShareWith(cfg, *alias)
	}
	fs.Visit(func(f *flag.Flag) { // only flags that were actually given change the node
		switch f.Name {
		case "advertise-ports":
			opts.AdvertiseSet = true
		case "bind":
			opts.Bind = bind
		case "proxy-protocol":
			opts.ProxyProtocol = proxyProto
		}
	})
	plan, tok, err := applyReverseIran(cfg, *alias, overrides, *publicIP, opts)
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
	forward := fs.Bool("forward", false, "restore the normal mode (the hub dials this foreign); the reverse settings are remembered")
	resume := fs.Bool("resume", false, "go back to reverse mode with the hubs and pipes it had; no token needed")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config (run this on the foreign; setup-foreign first)")
	}

	if *resume {
		if err := applyResumeForeign(cfg); err != nil {
			fail("%v", err)
		}
		if err := config.SaveConfig(cfg); err != nil {
			fail("failed to save config: %v", err)
		}
		color.Green("[✓] Reverse mode on again: dialing %d hub(s) with the saved settings.", len(cfg.EffectiveReverseHubs()))
		color.Yellow("    Make sure the hub node is in reverse mode too: hedioum-tunnel reverse-iran --alias NAME --resume")
		reconcileUnit("foreign")
		restartDaemon()
		return
	}

	if *forward {
		if err := applyForwardForeign(cfg); err != nil {
			fail("%v", err)
		}
		if err := config.SaveConfig(cfg); err != nil {
			fail("failed to save config: %v", err)
		}
		color.Green("[✓] Back to the normal mode: this foreign listens for the hub again.")
		color.Yellow("    The reverse settings are remembered: to switch back run reverse-foreign --resume")
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
