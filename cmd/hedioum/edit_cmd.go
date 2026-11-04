package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/persona"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

// conventionalPorts is the default port per mimic type when a config does not
// already pin one.
func conventionalPorts() map[string]int {
	return map[string]int{
		"ssh": 22, "tls": 443, "smtp": 587, "imap": 143, "smtps": 465, "imaps": 993,
		"directadmin": 2222, "https-alt": 8443, "docker": 5000, "grafana": 3000, "prometheus": 9090,
		"cpanel": 2083, "whm": 2087, "webmail": 2096, "postgres": 5432, "mysql": 3306,
	}
}

// currentForeignPorts returns the port per mimic type, using the foreign config's
// existing listeners where present and the conventional default otherwise.
func currentForeignPorts(cfg *config.AppConfig) map[string]int {
	ports := conventionalPorts()
	for _, m := range cfg.Mimics {
		ports[m.Type] = m.Port
	}
	return ports
}

// mimicTypesCSV lists a foreign config's mimic types as a comma string.
func mimicTypesCSV(ms []config.MimicListener) string {
	ts := make([]string, len(ms))
	for i, m := range ms {
		ts[i] = m.Type
	}
	return strings.Join(ts, ",")
}

// firstServerName returns the first non-empty TLS SNI/CN across a foreign config's
// mimics (they all share one).
func firstServerName(ms []config.MimicListener) string {
	for _, m := range ms {
		if m.ServerName != "" {
			return m.ServerName
		}
	}
	return ""
}

// buildForeignMimicList assembles listeners for the given types using the port map,
// the ssh decoy port, and the shared TLS SNI. Shared by setup-foreign and edit-foreign.
func buildForeignMimicList(types []string, ports map[string]int, decoyPort int, serverName string) []config.MimicListener {
	out := make([]config.MimicListener, 0, len(types))
	for _, ty := range types {
		ml := config.MimicListener{Type: ty, Port: ports[ty]}
		if ty == "ssh" {
			ml.Decoy = fmt.Sprintf("127.0.0.1:%d", decoyPort)
		} else {
			ml.ServerName = serverName
		}
		out = append(out, ml)
	}
	return out
}

// currentNodePorts returns the port per mimic type for one hub node's endpoints,
// falling back to the conventional default for absent types.
func currentNodePorts(node config.ForeignNode) map[string]int {
	ports := conventionalPorts()
	for _, e := range node.Endpoints {
		if _, ps, err := net.SplitHostPort(e.Target); err == nil {
			if p, err := strconv.Atoi(ps); err == nil {
				ports[e.Mimic] = p
			}
		}
	}
	return ports
}

// nodeMimicTypesCSV lists a node's endpoint mimic types as a comma string.
func nodeMimicTypesCSV(node config.ForeignNode) string {
	ts := make([]string, len(node.Endpoints))
	for i, e := range node.Endpoints {
		ts[i] = e.Mimic
	}
	return strings.Join(ts, ",")
}

// nodeTargetIP returns the host part of a node's first endpoint target.
func nodeTargetIP(node config.ForeignNode) string {
	if len(node.Endpoints) > 0 {
		if host, _, err := net.SplitHostPort(node.Endpoints[0].Target); err == nil {
			return host
		}
	}
	return node.TargetIP
}

// buildEndpoints assembles endpoints for the given types using the port map + SNI.
// Shared by add-node and edit-node.
func buildEndpoints(targetIP string, types []string, ports map[string]int, serverName string) []config.Endpoint {
	eps := make([]config.Endpoint, 0, len(types))
	for _, ty := range types {
		sni := ""
		if ty != "ssh" {
			sni = serverName
		}
		eps = append(eps, config.Endpoint{
			Target:     net.JoinHostPort(targetIP, strconv.Itoa(ports[ty])),
			Mimic:      ty,
			ServerName: sni,
		})
	}
	return eps
}

// extractArgValue does a light pre-scan for a flag's value (before the full flag set
// is defined), used so edit-node can load the selected node's current values and
// present them as defaults.
func extractArgValue(args []string, name string) string {
	for i, a := range args {
		switch {
		case a == "--"+name || a == "-"+name:
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "--"+name+"="):
			return a[len("--"+name+"="):]
		case strings.HasPrefix(a, "-"+name+"="):
			return a[len("-"+name+"="):]
		}
	}
	return ""
}

// resolveTokenEdit decides the auth token for an edit: an explicit --token wins, then
// --rotate-token generates a fresh one, otherwise the current token is preserved.
func resolveTokenEdit(current, explicit string, rotate bool) (string, string, error) {
	switch {
	case explicit != "":
		if err := validToken(explicit); err != nil {
			return "", "", err
		}
		return explicit, "set to the provided value", nil
	case rotate:
		return sysutil.GenerateSecureToken(), "rotated (regenerated)", nil
	default:
		return current, "unchanged", nil
	}
}

// cmdEditForeign edits the foreign (egress) config in place: every setup-foreign
// value defaults to the current one, so only the flags you pass change. The token is
// preserved unless --token or --rotate-token is given.
func cmdEditForeign(args []string) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config to edit (run setup-foreign first)")
	}
	ports := currentForeignPorts(cfg)
	decoyDefault := cfg.DecoyPort
	if decoyDefault == 0 {
		decoyDefault = 2022
	}

	fs := flag.NewFlagSet("edit-foreign", flag.ExitOnError)
	personaFlag := fs.String("persona", cfg.Persona, "server persona: auto|cpanel|directadmin|devops (re-resolves the mimic set)")
	mimics := fs.String("mimics", mimicTypesCSV(cfg.Mimics), "explicit camouflage set (overrides --persona): comma list or 'all'")
	sshPort := fs.Int("listen-port", ports["ssh"], "SSH mimic public port")
	tlsPort := fs.Int("tls-port", ports["tls"], "TLS mimic public port")
	smtpPort := fs.Int("smtp-port", ports["smtp"], "SMTP (STARTTLS) mimic public port")
	imapPort := fs.Int("imap-port", ports["imap"], "IMAP (STARTTLS) mimic public port")
	smtpsPort := fs.Int("smtps-port", ports["smtps"], "SMTPS mimic public port")
	imapsPort := fs.Int("imaps-port", ports["imaps"], "IMAPS mimic public port")
	daPort := fs.Int("directadmin-port", ports["directadmin"], "DirectAdmin panel mimic port")
	decoyPort := fs.Int("decoy-port", decoyDefault, "local decoy sshd port")
	tlsServerName := fs.String("tls-servername", firstServerName(cfg.Mimics), "TLS SNI/CN")
	domain := fs.String("domain", cfg.Domain, "real domain for a Let's Encrypt cert ('' = self-signed)")
	acmeEmail := fs.String("acme-email", cfg.ACMEEmail, "Let's Encrypt account email")
	decoyStyle := fs.String("decoy-style", cfg.DecoyStyle, "camouflage persona: apache|directadmin")
	egressMode := fs.String("egress-mode", cfg.EgressIPMode, "egress family: ipv4|ipv6|dual")
	bindIP := fs.String("egress-bind-ip", cfg.EgressBindIP, "egress source IP")
	httpDecoyPort := fs.Int("http-decoy-port", cfg.HTTPDecoyPort, "plaintext web decoy port (0 disables)")
	token := fs.String("token", "", "set a specific new auth token (default: keep current)")
	rotateToken := fs.Bool("rotate-token", false, "generate a fresh auth token")
	_ = fs.Parse(args)
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	switch *decoyStyle {
	case "apache", "directadmin":
	default:
		fail("--decoy-style must be apache or directadmin")
	}
	switch *egressMode {
	case "ipv4", "ipv6", "dual":
	default:
		fail("--egress-mode must be ipv4, ipv6, or dual")
	}
	if *bindIP != "" {
		if err := validIP(*bindIP); err != nil {
			fail("--egress-bind-ip: %v", err)
		}
	}
	newToken, tokenNote, err := resolveTokenEdit(cfg.AuthToken, *token, *rotateToken)
	if err != nil {
		fail("--token: %v", err)
	}

	// Decide the mimic set. An explicit --mimics wins (custom, clears the persona);
	// else an explicit --persona re-resolves from the (possibly rotated) token; else
	// keep the current persona (re-resolved, so it tracks port/token edits) or the
	// current custom set.
	var types []string
	switch {
	case setFlags["mimics"]:
		if types, err = expandMimics(*mimics); err != nil {
			fail("--mimics: %v", err)
		}
		cfg.Persona = ""
		if cerr := persona.CheckCoherence(types); cerr != nil {
			color.Yellow("[!] %v (an explicit --mimics set — proceeding anyway).", cerr)
		}
	case setFlags["persona"]:
		name := *personaFlag
		if name == "auto" || name == "" {
			name = persona.Auto(newToken)
		} else if !persona.Known(name) {
			fail("--persona must be auto|%s", strings.Join(persona.Names(), "|"))
		}
		if types, err = persona.Resolve(name, newToken); err != nil {
			fail("--persona: %v", err)
		}
		cfg.Persona = name
	case cfg.Persona != "":
		if types, err = persona.Resolve(cfg.Persona, newToken); err != nil {
			fail("--persona: %v", err)
		}
	default:
		if types, err = expandMimics(*mimics); err != nil {
			fail("--mimics: %v", err)
		}
	}

	portMap := map[string]int{"ssh": *sshPort, "tls": *tlsPort, "smtp": *smtpPort, "imap": *imapPort, "smtps": *smtpsPort, "imaps": *imapsPort, "directadmin": *daPort}
	// New-arsenal mimics keep their resolved port (conventional default or the value
	// already pinned in config); no extra flags.
	for _, ty := range []string{"https-alt", "docker", "grafana", "prometheus", "cpanel", "whm", "webmail", "postgres", "mysql"} {
		portMap[ty] = ports[ty]
	}
	for label, p := range portMap {
		if err := validPort(p); err != nil {
			fail("--%s-port: %v", label, err)
		}
	}

	cfg.Mimics = buildForeignMimicList(types, portMap, *decoyPort, *tlsServerName)
	cfg.ForeignListenPort = *sshPort
	cfg.DecoyPort = *decoyPort
	cfg.Domain = *domain
	cfg.ACMEEmail = *acmeEmail
	cfg.DecoyStyle = *decoyStyle
	cfg.EgressIPMode = *egressMode
	cfg.EgressBindIP = *bindIP
	hd := *httpDecoyPort
	if hd == 0 {
		hd = -1 // sentinel: disabled (0 would be re-defaulted to 80 on load)
	} else if err := validPort(hd); err != nil {
		fail("--http-decoy-port: %v", err)
	}
	cfg.HTTPDecoyPort = hd
	cfg.AuthToken = newToken

	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	color.Green("[✓] Foreign config updated (mimics: %s, domain: %q, style: %s).", strings.Join(types, ","), *domain, *decoyStyle)
	color.Cyan("    Auth token: %s (%s)", cfg.AuthToken, tokenNote)
	if tokenNote != "unchanged" {
		color.Yellow("    [!] The token changed — update every Iran hub node that dials this server.")
	}
	restartDaemon()
}

// cmdEditNode edits one hub node in place: every add-node value defaults to that
// node's current value, so only the flags you pass change. The token is preserved
// unless --token or --rotate-token is given.
func cmdEditNode(args []string) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "iran" {
		fail("no Iran hub config to edit (run setup-iran first)")
	}
	alias := extractArgValue(args, "alias")
	if alias == "" {
		fail("--alias is required (which node to edit)")
	}
	var node *config.ForeignNode
	for i := range cfg.ForeignNodes {
		if cfg.ForeignNodes[i].Alias == alias {
			node = &cfg.ForeignNodes[i]
			break
		}
	}
	if node == nil {
		fail("no node with alias %q", alias)
	}
	ports := currentNodePorts(*node)

	fs := flag.NewFlagSet("edit-node", flag.ExitOnError)
	_ = fs.String("alias", alias, "node alias to edit (required)")
	targetIP := fs.String("target-ip", nodeTargetIP(*node), "foreign egress IP")
	mimics := fs.String("mimics", nodeMimicTypesCSV(*node), "endpoints (comma list or 'all')")
	sshPort := fs.Int("ssh-port", ports["ssh"], "foreign SSH mimic port")
	tlsPort := fs.Int("tls-port", ports["tls"], "foreign TLS mimic port")
	smtpPort := fs.Int("smtp-port", ports["smtp"], "foreign SMTP mimic port")
	imapPort := fs.Int("imap-port", ports["imap"], "foreign IMAP mimic port")
	smtpsPort := fs.Int("smtps-port", ports["smtps"], "foreign SMTPS mimic port")
	imapsPort := fs.Int("imaps-port", ports["imaps"], "foreign IMAPS mimic port")
	daPort := fs.Int("directadmin-port", ports["directadmin"], "foreign DirectAdmin mimic port")
	tlsServerName := fs.String("tls-servername", firstEndpointSNI(*node), "TLS SNI (the foreign's domain, for a real cert)")
	socksPort := fs.Int("socks-port", node.LocalSocksPort, "local SOCKS5 bind port")
	socksBind := fs.String("socks-bind", node.SocksBind, "SOCKS5 bind address (container veth IP / 0.0.0.0 for LAN clients; trusted networks only)")
	minC := fs.Int("min", node.MinConnections, "min warm-up connections")
	maxC := fs.Int("max", node.MaxConnections, "max connections")
	bw := fs.Int("bw", node.BandwidthLimitMbps, "per-connection Mbps cap")
	jitter := fs.Int("jitter", node.BandwidthJitterMbps, "bandwidth jitter Mbps")
	token := fs.String("token", "", "set a specific new auth token (default: keep current)")
	rotateToken := fs.Bool("rotate-token", false, "generate a fresh auth token")
	tun := fs.Bool("tun", node.TunEnabled, "expose this node as a TUN interface (opt-in)")
	tunName := fs.String("tun-name", node.TunName, "TUN interface name (default: keep/auto)")
	tunAddr := fs.String("tun-addr", node.TunAddr, "TUN gateway CIDR (default: keep/auto)")
	dns := fs.Bool("dns", node.DNSEnabled, "run a :53 DNS forwarder on the TUN gateway IP (requires --tun)")
	gateway := fs.Bool("gateway", node.GatewayEnabled, "transparent L3 gateway: forward transit traffic on the LAN iface into the tunnel (implies --tun)")
	gatewayIface := fs.String("gateway-iface", node.GatewayIface, "LAN-facing interface to forward from (default: auto)")
	gatewayLAN := fs.String("gateway-lan", strings.Join(node.GatewayLAN, ","), "comma-list of LAN subnets to scope forwarding (default: all transit)")
	_ = fs.Parse(args)

	if *targetIP == "" {
		fail("--target-ip must not be empty")
	}
	if *dns && !*tun && !*gateway {
		fail("--dns requires --tun")
	}
	// Resolve TUN settings, auto-assigning a free interface/subnet when enabling
	// without an explicit one; disabling clears the fields. Gateway implies TUN.
	tunEnabled := *tun || *gateway
	tName, tAddr := *tunName, *tunAddr
	if tunEnabled {
		if tName == "" || tAddr == "" {
			autoName, autoAddr := nextFreeTun(cfg)
			if tName == "" {
				tName = autoName
			}
			if tAddr == "" {
				tAddr = autoAddr
			}
		}
		if _, _, err := net.ParseCIDR(tAddr); err != nil {
			fail("--tun-addr: %v", err)
		}
	} else {
		tName, tAddr = "", ""
	}
	var gatewayLANs []string
	if *gatewayLAN != "" {
		for _, s := range strings.Split(*gatewayLAN, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(s); err != nil {
				fail("--gateway-lan: invalid subnet %q: %v", s, err)
			}
			gatewayLANs = append(gatewayLANs, s)
		}
	}
	types, err := expandMimics(*mimics)
	if err != nil {
		fail("--mimics: %v", err)
	}
	portMap := map[string]int{"ssh": *sshPort, "tls": *tlsPort, "smtp": *smtpPort, "imap": *imapPort, "smtps": *smtpsPort, "imaps": *imapsPort, "directadmin": *daPort}
	// New-arsenal mimics (https-alt/docker/postgres/mysql) keep their resolved port
	// (conventional default or the value already pinned in config); no extra flags.
	for _, ty := range []string{"https-alt", "docker", "grafana", "prometheus", "cpanel", "whm", "webmail", "postgres", "mysql"} {
		portMap[ty] = ports[ty]
	}
	for label, p := range portMap {
		if err := validPort(p); err != nil {
			fail("--%s-port: %v", label, err)
		}
	}
	if err := validPort(*socksPort); err != nil {
		fail("--socks-port: %v", err)
	}
	newToken, tokenNote, err := resolveTokenEdit(node.AuthToken, *token, *rotateToken)
	if err != nil {
		fail("--token: %v", err)
	}

	cfg.UpdateForeignNode(config.ForeignNode{
		Alias:               alias,
		LocalSocksPort:      *socksPort,
		SocksBind:           *socksBind,
		AuthToken:           newToken,
		Endpoints:           buildEndpoints(*targetIP, types, portMap, *tlsServerName),
		TunEnabled:          tunEnabled,
		TunName:             tName,
		TunAddr:             tAddr,
		DNSEnabled:          *dns,
		GatewayEnabled:      *gateway,
		GatewayIface:        *gatewayIface,
		GatewayLAN:          gatewayLANs,
		MinConnections:      *minC,
		MaxConnections:      *maxC,
		BandwidthLimitMbps:  *bw,
		BandwidthJitterMbps: *jitter,
	})
	if err := config.SaveConfig(cfg); err != nil {
		fail("failed to save config: %v", err)
	}
	color.Green("[✓] Node %q updated (target %s, mimics: %s, socks %d).", alias, *targetIP, strings.Join(types, ","), *socksPort)
	if tunEnabled {
		color.Cyan("    TUN: %s @ %s%s", tName, tAddr, map[bool]string{true: ", DNS :53", false: ""}[*dns])
	}
	color.Cyan("    Auth token: %s", tokenNote)
	reconcileUnit("iran")
	restartDaemon()
}

// firstEndpointSNI returns the first non-empty endpoint SNI for a node.
func firstEndpointSNI(node config.ForeignNode) string {
	for _, e := range node.Endpoints {
		if e.ServerName != "" {
			return e.ServerName
		}
	}
	return ""
}
