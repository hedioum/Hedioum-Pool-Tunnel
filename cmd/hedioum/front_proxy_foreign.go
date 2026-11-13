package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

// Front-proxy support for the FOREIGN (direct tunnel mode): the foreign's listeners can
// sit behind an nginx stream / HAProxy that owns a shared public port such as 443 and
// forwards the tunnel's SNI to the listener. The settings are ListenBind, ProxyProtocol
// and AdvertisePorts on the foreign config.

const (
	// defaultFrontProxyOffset is the distance between a mimic's public port and the local
	// port it listens on behind a front proxy (8443 -> 48443, 143 -> 40143, 2020 -> 42020).
	defaultFrontProxyOffset = 40000
	// sharedFrontPort is the public port a front proxy shares with other services (a
	// panel, user configs) and so routes by SNI. Any other advertised port is a dedicated
	// forward: the proxy listens on it for this tunnel listener alone, no SNI needed.
	sharedFrontPort = 443
)

// parseTypePortList parses "tls=443,https-alt=8443" into a type->port map (any valid
// mimic type, SSH included). An empty spec is an empty map.
func parseTypePortList(spec string) (map[string]int, error) {
	out := map[string]int{}
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
		if !validMimicType(ty) {
			return nil, fmt.Errorf("%q is not a mimic type", ty)
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

// formatTypePorts renders a type->port map as "tls=443,https-alt=8443" (sorted).
func formatTypePorts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, ",")
}

// foreignSNI is the SNI the foreign's hub-facing endpoints use.
func foreignSNI(cfg *config.AppConfig) string {
	if sni := firstServerName(cfg.Mimics); sni != "" {
		return sni
	}
	return cfg.Domain
}

// foreignProxyOpts are the front-proxy settings for a foreign; nil/false keeps current.
type foreignProxyOpts struct {
	Bind          *string
	ProxyProtocol *bool
	Advertise     map[string]int
	AdvertiseSet  bool
}

// applyForeignFrontProxy validates and stores the front-proxy settings in cfg.
func applyForeignFrontProxy(cfg *config.AppConfig, o foreignProxyOpts) ([]string, error) {
	if o.Bind != nil {
		if err := validBind(*o.Bind); err != nil {
			return nil, fmt.Errorf("--bind: %v", err)
		}
	}
	adv := cfg.AdvertisePorts
	if o.AdvertiseSet {
		adv = o.Advertise
	}
	if len(adv) > 0 {
		types := map[string]bool{}
		for _, m := range cfg.Mimics {
			types[m.Type] = true
		}
		seen := map[int]string{}
		for ty, p := range adv {
			if ty == "ssh" || !types[ty] {
				return nil, fmt.Errorf("--advertise-ports %s: the foreign has no such TLS listener (SSH cannot be routed by SNI)", ty)
			}
			if err := validPort(p); err != nil {
				return nil, fmt.Errorf("--advertise-ports %s: %v", ty, err)
			}
			if other, dup := seen[p]; dup {
				return nil, fmt.Errorf("--advertise-ports: %s and %s both use port %d, but a front proxy routes one SNI to one listener; advertise a single type per port", other, ty, p)
			}
			seen[p] = ty
		}
		for ty, p := range adv {
			if p == sharedFrontPort && foreignSNI(cfg) == "" {
				return nil, fmt.Errorf("%s is advertised on the shared port %d, which a front proxy routes by SNI: set one first (--tls-servername NAME)", ty, sharedFrontPort)
			}
		}
	}
	var warns []string
	if o.Bind != nil {
		cfg.ListenBind = *o.Bind
	}
	if o.ProxyProtocol != nil {
		cfg.ProxyProtocol = *o.ProxyProtocol
	}
	if len(adv) == 0 {
		cfg.AdvertisePorts = nil
	} else {
		cfg.AdvertisePorts = map[string]int{}
		for ty, p := range adv {
			cfg.AdvertisePorts[ty] = p
		}
	}
	if cfg.ProxyProtocol && !isLoopbackBind(cfg.ListenBind) {
		warns = append(warns, "PROXY protocol is required but the listeners are not bound to a loopback address: anything reaching them directly is dropped, so also use --bind 127.0.0.1")
	}
	if len(cfg.AdvertisePorts) > 0 && !isLoopbackBind(cfg.ListenBind) {
		warns = append(warns, "a front proxy is in use but the listeners are still reachable directly; --bind 127.0.0.1 keeps them behind the proxy")
	}
	return warns, nil
}

// foreignFrontSpec describes the foreign's tunnel listener that the front proxy routes by
// SNI: the one advertised on the shared port (443), or, with no advertised ports at all,
// the first TLS listener. It returns errNoSNIListener when every proxied listener has a
// port of its own.
func foreignFrontSpec(cfg *config.AppConfig) (frontSpec, error) {
	var pick *config.MimicListener
	for i := range cfg.Mimics {
		m := &cfg.Mimics[i]
		if m.Type == "ssh" {
			continue
		}
		if cfg.AdvertisePorts[m.Type] == sharedFrontPort {
			pick = m
			break
		}
		if pick == nil && len(cfg.AdvertisePorts) == 0 {
			pick = m
		}
	}
	if pick == nil {
		if len(cfg.AdvertisePorts) > 0 {
			return frontSpec{}, errNoSNIListener
		}
		return frontSpec{}, fmt.Errorf("the foreign has no TLS listener to front")
	}
	sni := foreignSNI(cfg)
	if sni == "" {
		return frontSpec{}, fmt.Errorf("no SNI configured: a front proxy routes by SNI (edit-foreign --tls-servername NAME)")
	}
	return frontSpec{Upstream: net.JoinHostPort(localHost(cfg), strconv.Itoa(pick.Port)), SNI: sni, ProxyProtocol: cfg.ProxyProtocol}, nil
}

var errNoSNIListener = fmt.Errorf("no listener is routed by SNI")

// localHost is the address the proxy forwards to: the listener bind, or loopback.
func localHost(cfg *config.AppConfig) string {
	host := cfg.ListenBind
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	return host
}

// dedicatedForward is a proxied listener that has a public port of its own: the proxy
// listens on Public and forwards every connection to Upstream. No SNI is involved.
type dedicatedForward struct {
	Type     string
	Public   int
	Upstream string
}

// foreignDedicatedForwards lists the proxied listeners that are not on the shared port,
// sorted by public port.
func foreignDedicatedForwards(cfg *config.AppConfig) []dedicatedForward {
	var out []dedicatedForward
	for _, m := range cfg.Mimics {
		pub, ok := cfg.AdvertisePorts[m.Type]
		if !ok || m.Type == "ssh" || pub == sharedFrontPort {
			continue
		}
		out = append(out, dedicatedForward{Type: m.Type, Public: pub, Upstream: net.JoinHostPort(localHost(cfg), strconv.Itoa(m.Port))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Public < out[j].Public })
	return out
}

// nginxDedicated renders one stream server per dedicated forward.
func nginxDedicated(fw []dedicatedForward, proxyProtocol bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nginx: one stream server per listener that has its own public port (no SNI needed).\n")
	fmt.Fprintf(&b, "# Put these inside your existing `stream { ... }` block (or a new one):\n\n")
	for _, f := range fw {
		fmt.Fprintf(&b, "    server {   # %s\n        listen %d;\n        proxy_pass %s;\n", f.Type, f.Public, f.Upstream)
		if proxyProtocol {
			fmt.Fprintf(&b, "        proxy_protocol on;\n")
		}
		fmt.Fprintf(&b, "    }\n")
	}
	return b.String()
}

// haproxyDedicated renders one frontend/backend pair per dedicated forward.
func haproxyDedicated(fw []dedicatedForward, proxyProtocol bool) string {
	send := ""
	if proxyProtocol {
		send = " send-proxy"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HAProxy: one frontend per listener that has its own public port (no SNI needed)\n")
	for _, f := range fw {
		fmt.Fprintf(&b, "frontend hedioum_%s_%d\n    bind :%d\n    mode tcp\n    default_backend hedioum_%s_%d\n\n", f.Type, f.Public, f.Public, f.Type, f.Public)
		fmt.Fprintf(&b, "backend hedioum_%s_%d\n    mode tcp\n    server hub %s%s\n\n", f.Type, f.Public, f.Upstream, send)
	}
	return b.String()
}

// autoFrontProxy puts the chosen mimic types behind the front proxy in one step: each
// keeps its current public port (what a hub dials) and moves its listener to public+offset
// on the loopback address (8443 -> 48443, 143 -> 40143), with PROXY protocol if asked.
// types may be empty or ["all"] for every non-SSH listener. Types not chosen are left as
// they are. Running it again is harmless.
func autoFrontProxy(cfg *config.AppConfig, types []string, offset int, proxyProtocol bool) ([]string, error) {
	if offset < 1 || offset > 60000 {
		return nil, fmt.Errorf("the port offset must be between 1 and 60000")
	}
	have := map[string]int{} // type -> index in cfg.Mimics
	for i, m := range cfg.Mimics {
		if m.Type != "ssh" {
			have[m.Type] = i
		}
	}
	sel := map[string]bool{}
	for _, ty := range types {
		ty = strings.TrimSpace(ty)
		if ty == "" {
			continue
		}
		if ty == "all" {
			for t := range have {
				sel[t] = true
			}
			continue
		}
		if _, ok := have[ty]; !ok {
			return nil, fmt.Errorf("--front-proxy-auto %s: the foreign has no such TLS listener (SSH cannot be routed by SNI)", ty)
		}
		sel[ty] = true
	}
	if len(sel) == 0 {
		for t := range have {
			sel[t] = true
		}
	}
	adv := map[string]int{}
	for ty, p := range cfg.AdvertisePorts {
		adv[ty] = p
	}
	used := map[int]string{}
	for _, m := range cfg.Mimics {
		used[m.Port] = m.Type
	}
	moved := map[string]int{}
	for ty := range sel {
		m := &cfg.Mimics[have[ty]]
		pub, ok := adv[ty]
		if !ok {
			pub = m.Port
			// A port the operator already moved behind the proxy by hand (for example
			// 40143 for imap) is the LOCAL port: the public one is that minus the offset.
			if m.Port > offset && (cfg.ListenBind != "" || cfg.ProxyProtocol || m.Port+offset > 65535) {
				pub = m.Port - offset
			}
		}
		local := pub + offset
		if local > 65535 {
			return nil, fmt.Errorf("%s: public port %d + offset %d is above 65535; use a smaller --front-proxy-offset", ty, pub, offset)
		}
		if other, taken := used[local]; taken && other != ty {
			return nil, fmt.Errorf("%s: local port %d is already used by the %s listener", ty, local, other)
		}
		adv[ty] = pub
		moved[ty] = local
	}
	for ty, local := range moved {
		cfg.Mimics[have[ty]].Port = local
	}
	bind := "127.0.0.1"
	return applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: &bind, ProxyProtocol: &proxyProtocol, Advertise: adv, AdvertiseSet: true})
}

// removeFrontProxy takes the chosen types out from behind the proxy: each listener goes
// back to its public port and is no longer advertised separately. When no type is left
// behind the proxy, the bind address and PROXY protocol are cleared too.
func removeFrontProxy(cfg *config.AppConfig, types []string) error {
	adv := map[string]int{}
	for ty, p := range cfg.AdvertisePorts {
		adv[ty] = p
	}
	for _, ty := range types {
		ty = strings.TrimSpace(ty)
		if ty == "" {
			continue
		}
		pub, ok := adv[ty]
		if !ok {
			return fmt.Errorf("%s is not behind the front proxy", ty)
		}
		for i := range cfg.Mimics {
			if cfg.Mimics[i].Type == ty {
				cfg.Mimics[i].Port = pub
			}
		}
		delete(adv, ty)
	}
	empty, off := "", false
	if len(adv) == 0 {
		_, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: &empty, ProxyProtocol: &off, AdvertiseSet: true})
		return err
	}
	_, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Advertise: adv, AdvertiseSet: true})
	return err
}

// foreignPairingToken builds the paste-only pairing token for the hub, with advertised
// ports in place of the listener ports.
func foreignPairingToken(cfg *config.AppConfig, exitIP string) string {
	eps := map[string]int{}
	for _, m := range cfg.Mimics {
		p := m.Port
		if ap, ok := cfg.AdvertisePorts[m.Type]; ok {
			p = ap
		}
		eps[m.Type] = p
	}
	return pairing.Encode(pairing.Token{ExitIP: exitIP, AuthKey: cfg.AuthToken, Persona: cfg.Persona, SNI: foreignSNI(cfg), Endpoints: eps})
}

// printHubHintForForeign tells the operator how to point the hub at the proxy.
func printHubHintForForeign(cfg *config.AppConfig, sp frontSpec, publicPort int) {
	ty := ""
	for _, m := range cfg.Mimics {
		if net.JoinHostPort("127.0.0.1", strconv.Itoa(m.Port)) == sp.Upstream || net.JoinHostPort(cfg.ListenBind, strconv.Itoa(m.Port)) == sp.Upstream {
			ty = m.Type
			break
		}
	}
	color.HiCyan("# On the Iran hub, point the node at the proxy (port and SNI):")
	if ty != "" {
		fmt.Printf("hedioum-tunnel edit-node --alias NAME --ports %s=%d --tls-servername %s\n", ty, publicPort, sp.SNI)
	}
	fmt.Println("# or print a fresh paste-only token with `hedioum-tunnel pairing-token` on this foreign.")
}

// printDedicatedHubHint tells the operator how a hub reaches the listeners that have a
// public port of their own.
func printDedicatedHubHint(fw []dedicatedForward) {
	color.HiCyan("# Listeners with their own public port: a hub dials that port, no SNI involved")
	for _, f := range fw {
		fmt.Printf("hedioum-tunnel edit-node --alias NAME --ports %s=%d\n", f.Type, f.Public)
	}
	fmt.Println("# or print a fresh paste-only token with `hedioum-tunnel pairing-token` on this foreign.")
}

// cmdPairingToken prints the pairing token of the current foreign config.
func cmdPairingToken(args []string) {
	fs := flag.NewFlagSet("pairing-token", flag.ExitOnError)
	publicIP := fs.String("public-ip", "", "this foreign's public IP (auto-detected if empty)")
	_ = fs.Parse(args)
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config (run this on the foreign)")
	}
	ip := *publicIP
	if ip == "" {
		if detected, derr := sysutil.GetPublicIPv4(); derr == nil {
			ip = detected
		}
	}
	if ip == "" {
		fail("could not detect this server's public IP; pass --public-ip")
	}
	if err := validIP(ip); err != nil {
		fail("--public-ip: %v", err)
	}
	fmt.Println(foreignPairingToken(cfg, ip))
}

// runForeignFrontProxyMenu is the foreign's interactive front-proxy entry.
func runForeignFrontProxyMenu(cfg *config.AppConfig) {
	var choice string
	_ = survey.AskOne(&survey.Select{
		Message: "Front proxy (nginx / HAProxy sharing a port such as 443):",
		Options: []string{
			"Choose which mimics go behind the proxy (ports are assigned automatically)",
			"Show the nginx / HAProxy config",
			"Remove the front-proxy settings",
			"Cancel",
		},
	}, &choice)
	switch {
	case strings.HasPrefix(choice, "Show"):
		showForeignFrontProxy(cfg)
	case strings.HasPrefix(choice, "Remove"):
		empty, pp := "", false
		if _, err := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: &empty, ProxyProtocol: &pp, AdvertiseSet: true}); err != nil {
			color.Red("[x] %v", err)
			return
		}
		saveAndRestart(cfg)
	case strings.HasPrefix(choice, "Choose"):
		runChooseFrontProxied(cfg)
	}
}

// runChooseFrontProxied lets the operator tick the mimic types that go behind the
// proxy, in one screen: ports are assigned automatically (local = public + 40000) and
// the types left unticked keep their public listener.
func runChooseFrontProxied(cfg *config.AppConfig) {
	var types, cur []string
	for _, m := range cfg.Mimics {
		if m.Type == "ssh" {
			continue
		}
		types = append(types, m.Type)
		if cfg.FrontProxied(m.Type) {
			cur = append(cur, m.Type)
		}
	}
	if len(types) == 0 {
		color.Red("[x] The foreign has no TLS listener; enable a TLS mimic first (Edit Foreign Configuration).")
		return
	}
	var picked []string
	if err := survey.AskOne(&survey.MultiSelect{
		Message: "Which mimics go behind the front proxy? (space to tick; the others stay public; SSH never goes behind it)",
		Options: types,
		Default: cur,
	}, &picked); err != nil {
		return
	}
	pp := cfg.ProxyProtocol
	if len(cfg.AdvertisePorts) == 0 {
		pp = true
	}
	if len(picked) > 0 {
		_ = survey.AskOne(&survey.Confirm{Message: "Does your proxy send the PROXY protocol? (nginx: `proxy_protocol on;` in the stream server)", Default: pp}, &pp)
	}
	// Types that were behind the proxy and are no longer ticked go back to public.
	keep := map[string]bool{}
	for _, t := range picked {
		keep[t] = true
	}
	var drop []string
	for _, t := range cur {
		if !keep[t] {
			drop = append(drop, t)
		}
	}
	if len(drop) > 0 {
		if err := removeFrontProxy(cfg, drop); err != nil {
			color.Red("[x] %v", err)
			return
		}
	}
	if len(picked) > 0 {
		// The type on the shared port is routed by SNI and needs one; the rest do not.
		for i, m := range cfg.Mimics {
			pub := cfg.AdvertisePorts[m.Type]
			if pub == 0 {
				pub = m.Port
			}
			if keep[m.Type] && pub == sharedFrontPort && foreignSNI(cfg) == "" {
				sni := ""
				_ = survey.AskOne(&survey.Input{Message: fmt.Sprintf("SNI that identifies the tunnel on port %d (a name not used by your other services):", sharedFrontPort)}, &sni)
				sni = strings.TrimSpace(sni)
				if sni == "" {
					color.Red("[x] An SNI is required for the listener on port %d.", sharedFrontPort)
					return
				}
				cfg.Mimics[i].ServerName = sni
			}
		}
		warns, err := autoFrontProxy(cfg, picked, defaultFrontProxyOffset, pp)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		for _, w := range warns {
			color.Yellow("[!] %s", w)
		}
	}
	saveAndRestart(cfg)
	showForeignFrontProxy(cfg)
}

// showForeignFrontProxy prints the proxy configs and the hub-side instructions.
func showForeignFrontProxy(cfg *config.AppConfig) {
	sp, err := foreignFrontSpec(cfg)
	if err != nil && !errors.Is(err, errNoSNIListener) {
		color.Red("[x] %v", err)
		return
	}
	fmt.Println()
	if err == nil {
		fmt.Println(nginxFor(sp, sharedFrontPort))
		fmt.Println(haproxyFor(sp, sharedFrontPort))
		printHubHintForForeign(cfg, sp, sharedFrontPort)
	}
	if fw := foreignDedicatedForwards(cfg); len(fw) > 0 {
		fmt.Println(nginxDedicated(fw, cfg.ProxyProtocol))
		fmt.Println(haproxyDedicated(fw, cfg.ProxyProtocol))
		printDedicatedHubHint(fw)
	}
}
