package main

import (
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
		if foreignSNI(cfg) == "" {
			return nil, fmt.Errorf("a front proxy routes by SNI: set one first (--tls-servername NAME)")
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
	if isLoopbackBind(cfg.ListenBind) {
		for _, m := range cfg.Mimics {
			if _, ok := cfg.AdvertisePorts[m.Type]; !ok && m.Type != "ssh" {
				warns = append(warns, fmt.Sprintf("the %s listener is bound to loopback but not advertised, so a hub cannot reach it; remove it from the mimic set or advertise it", m.Type))
			}
		}
	}
	return warns, nil
}

// foreignFrontSpec describes the foreign's tunnel listener for a front proxy: the
// advertised TLS listener (or the first TLS one) and the SNI.
func foreignFrontSpec(cfg *config.AppConfig) (frontSpec, error) {
	sni := foreignSNI(cfg)
	if sni == "" {
		return frontSpec{}, fmt.Errorf("no SNI configured: a front proxy routes by SNI (edit-foreign --tls-servername NAME)")
	}
	var pick *config.MimicListener
	for i := range cfg.Mimics {
		m := &cfg.Mimics[i]
		if m.Type == "ssh" {
			continue
		}
		if _, adv := cfg.AdvertisePorts[m.Type]; adv {
			pick = m
			break
		}
		if pick == nil {
			pick = m
		}
	}
	if pick == nil {
		return frontSpec{}, fmt.Errorf("the foreign has no TLS listener to front")
	}
	host := cfg.ListenBind
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	return frontSpec{Upstream: net.JoinHostPort(host, strconv.Itoa(pick.Port)), SNI: sni, ProxyProtocol: cfg.ProxyProtocol}, nil
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
			"Set up / change",
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
	case strings.HasPrefix(choice, "Set up"):
		var types []string
		for _, m := range cfg.Mimics {
			if m.Type != "ssh" {
				types = append(types, m.Type)
			}
		}
		if len(types) == 0 {
			color.Red("[x] The foreign has no TLS listener; enable a TLS mimic first (Edit Foreign Configuration).")
			return
		}
		ty := types[0]
		if len(types) > 1 {
			_ = survey.AskOne(&survey.Select{Message: "A proxy routes one SNI to one listener. Which mimic type?", Options: types}, &ty)
		}
		sni := foreignSNI(cfg)
		_ = survey.AskOne(&survey.Input{Message: "SNI that identifies the tunnel (a name not used by your other services):", Default: sni}, &sni)
		sni = strings.TrimSpace(sni)
		if sni == "" {
			color.Red("[x] An SNI is required.")
			return
		}
		portStr := "443"
		_ = survey.AskOne(&survey.Input{Message: "Public port the proxy listens on (what the hub dials):", Default: "443"}, &portStr)
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || validPort(port) != nil {
			color.Red("[x] Invalid port.")
			return
		}
		// The tunnel's own (local) port: the proxy forwards to it, so it must differ from
		// the proxy's public port when both run on this host.
		curLocal := 0
		for _, m := range cfg.Mimics {
			if m.Type == ty {
				curLocal = m.Port
			}
		}
		if curLocal == port || curLocal == 0 {
			curLocal = 8443
			if port == 8443 {
				curLocal = 2053
			}
		}
		localStr := strconv.Itoa(curLocal)
		_ = survey.AskOne(&survey.Input{Message: "Port the tunnel listens on locally (the proxy forwards to it):", Default: localStr}, &localStr)
		localPort, lerr := strconv.Atoi(strings.TrimSpace(localStr))
		if lerr != nil || validPort(localPort) != nil {
			color.Red("[x] Invalid port.")
			return
		}
		if localPort == port {
			color.Red("[x] The local port must differ from the proxy's public port (%d).", port)
			return
		}
		pp := false
		_ = survey.AskOne(&survey.Confirm{Message: "Does your proxy send the PROXY protocol? (nginx: `proxy_protocol on;` in the stream server)", Default: false}, &pp)
		local := true
		_ = survey.AskOne(&survey.Confirm{Message: "Bind the listeners to 127.0.0.1 so they are only reachable through the proxy?", Default: true}, &local)
		bind := ""
		if local {
			bind = "127.0.0.1"
		}
		for i := range cfg.Mimics {
			if cfg.Mimics[i].Type != "ssh" {
				cfg.Mimics[i].ServerName = sni
			}
			if cfg.Mimics[i].Type == ty {
				cfg.Mimics[i].Port = localPort
			}
		}
		warns, aerr := applyForeignFrontProxy(cfg, foreignProxyOpts{Bind: &bind, ProxyProtocol: &pp, Advertise: map[string]int{ty: port}, AdvertiseSet: true})
		if aerr != nil {
			color.Red("[x] %v", aerr)
			return
		}
		for _, w := range warns {
			color.Yellow("[!] %s", w)
		}
		saveAndRestart(cfg)
		showForeignFrontProxy(cfg)
	}
}

// showForeignFrontProxy prints the proxy configs and the hub-side instructions.
func showForeignFrontProxy(cfg *config.AppConfig) {
	sp, err := foreignFrontSpec(cfg)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	port := 443
	for _, p := range cfg.AdvertisePorts {
		port = p
		break
	}
	fmt.Println()
	fmt.Println(nginxFor(sp, port))
	fmt.Println(haproxyFor(sp, port))
	printHubHintForForeign(cfg, sp, port)
}
