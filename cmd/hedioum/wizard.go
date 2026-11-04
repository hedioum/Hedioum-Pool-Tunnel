package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/pairing"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/persona"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

func handleReset() {
	if err := os.Remove("/etc/hedioum/hedioum.json"); err != nil && !os.IsNotExist(err) {
		os.Remove("hedioum.json") // Fallback to local directory
	}
	color.Yellow("[-] Configuration purged. Resetting daemon state...\n")
	exec.Command("systemctl", "stop", "hedioum.service").Run()
}

func runSetupWizard() *config.AppConfig {
	var role string
	prompt := &survey.Select{
		Message: "Define the network role of this server instance:",
		Options: []string{"Foreign Egress Node (Target)", "Iran Hub Node (Ingress)"},
	}
	survey.AskOne(prompt, &role)

	cfg := &config.AppConfig{}

	if role == "Foreign Egress Node (Target)" {
		cfg.Role = "foreign"
		setupForeignNode(cfg)
	} else {
		cfg.Role = "iran"
		setupIranNode(cfg, true)
	}

	if err := config.SaveConfig(cfg); err != nil {
		color.Red("[x] Fatal: Failed to persist state: %v", err)
		os.Exit(1)
	}
	// Align the systemd sandbox with the role: the hub is TUN-capable (CAP_NET_ADMIN),
	// the foreign stays locked to CAP_NET_BIND_SERVICE.
	reconcileUnit(cfg.Role)
	color.Green("\n[✓] State provisioned successfully.")
	return cfg
}

func setupForeignNode(cfg *config.AppConfig) {
	color.HiBlue("\n--- Foreign Egress Provisioning ---")
	detectedIP, _ := sysutil.GetPublicIPv4()

	var ip string
	survey.AskOne(&survey.Input{
		Message: "Confirm Server Public IPv4:",
		Default: detectedIP,
	}, &ip, survey.WithValidator(survey.Required))

	// Choose a coherent server persona (SSH + 9 mimics) seeded from the token, or a
	// custom mimic set. The token is generated now so it can seed the persona.
	token := sysutil.GenerateSecureToken()
	var personaChoice string
	survey.AskOne(&survey.Select{
		Message: "Server persona (shapes the whole on-wire footprint):",
		Options: append([]string{"auto (recommended)"}, append(persona.Names(), "custom (choose mimics)")...),
		Default: "auto (recommended)",
		Help:    "auto = a coherent persona seeded from your token. cpanel/directadmin/devops force one. custom = pick individual mimics.",
	}, &personaChoice)

	var mimics []string
	chosenPersona := ""
	if strings.HasPrefix(personaChoice, "custom") {
		mimics = promptMimics()
	} else {
		chosenPersona = strings.Fields(personaChoice)[0] // "auto"/"cpanel"/...
		if chosenPersona == "auto" {
			chosenPersona = persona.Auto(token)
		}
		var err error
		if mimics, err = persona.Resolve(chosenPersona, token); err != nil {
			color.Red("[x] persona %q: %v — falling back to a manual selection.", chosenPersona, err)
			chosenPersona, mimics = "", promptMimics()
		} else {
			color.Green("[✓] Persona %q: %s", chosenPersona, strings.Join(mimics, ", "))
		}
	}

	// SSH-specific prompts only matter when the SSH mimic is enabled.
	listenPort := 22
	decoyPort := 2022
	if containsStr(mimics, "ssh") {
		var listenPortStr string
		survey.AskOne(&survey.Input{Message: "SSH mimic public port:", Default: "22"}, &listenPortStr)
		listenPort = clampPort(listenPortStr, 22)
		if listenPort != 22 {
			color.Yellow("[!] SSH mimic on port %d: it is most convincing on 22.", listenPort)
		}

		var decoyPortStr string
		survey.AskOne(&survey.Input{Message: "Decoy sshd port (OpenSSH is moved here):", Default: "2022"}, &decoyPortStr)
		decoyPort = clampPort(decoyPortStr, 2022)

		changeSSH := false
		survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Move OpenSSH to port %d to free port %d for the SSH mimic?", decoyPort, listenPort),
			Default: true,
		}, &changeSSH)
		if changeSSH {
			if err := sysutil.ChangeSSHPort(strconv.Itoa(decoyPort)); err != nil {
				color.Red("[x] OpenSSH port relocation failed: %v", err)
			} else {
				color.Green("[✓] OpenSSH shifted to %d. Decoy port available.", decoyPort)
			}
		}
	}

	// Build one listener per selected mimic on its conventional port.
	var mimicList []config.MimicListener
	for _, ty := range mimics {
		ml := config.MimicListener{Type: ty, Port: mimicPort(ty, listenPort)}
		if ty == "ssh" {
			ml.Decoy = fmt.Sprintf("127.0.0.1:%d", decoyPort)
		}
		mimicList = append(mimicList, ml)
	}

	cfg.ForeignListenPort = listenPort
	cfg.DecoyPort = decoyPort
	cfg.Mimics = mimicList
	cfg.Persona = chosenPersona
	cfg.AuthToken = token

	// IPv6 egress is opt-in (default IPv4-only to avoid leaking the v6 identity).
	cfg.EgressIPMode = "ipv4"
	if v6, err := sysutil.GetPublicIPv6(); err == nil && v6 != "" {
		enableV6 := false
		survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Detected IPv6 (%s). Allow outbound traffic over IPv6 too?", v6),
			Default: false,
		}, &enableV6)
		if enableV6 {
			var mode string
			survey.AskOne(&survey.Select{
				Message: "Egress IP mode:",
				Options: []string{"Dual (prefer IPv4, fall back to IPv6)", "IPv6 only"},
			}, &mode)
			if strings.HasPrefix(mode, "IPv6") {
				cfg.EgressIPMode = "ipv6"
			} else {
				cfg.EgressIPMode = "dual"
			}
		}
	}

	// TLS certificate: a real domain (Let's Encrypt) vs self-signed.
	color.HiWhite("\n--- TLS Certificate ---")
	color.White("  A domain pointed at THIS server lets the tunnel present a genuine Let's")
	color.White("  Encrypt certificate — far harder to fingerprint than a self-signed one.")
	color.White("  Without a domain everything still works, using a self-signed certificate.")
	domain := ""
	survey.AskOne(&survey.Input{Message: "Domain for a real certificate (blank = self-signed):"}, &domain)
	cfg.Domain = strings.TrimSpace(domain)
	if cfg.Domain != "" {
		email := ""
		survey.AskOne(&survey.Input{Message: "Let's Encrypt account email (optional):"}, &email)
		cfg.ACMEEmail = strings.TrimSpace(email)
	} else {
		color.Yellow("  [!] Using a self-signed certificate. A domain is recommended when possible.")
	}

	// Web-decoy style shown to unauthorized probes on the plain web ports.
	decoyStyle := ""
	survey.AskOne(&survey.Select{
		Message: "Web-decoy style for unauthorized probes:",
		Options: []string{"apache (Apache default page)", "directadmin (DirectAdmin hosting box)"},
		Default: "apache (Apache default page)",
	}, &decoyStyle)
	if strings.HasPrefix(decoyStyle, "directadmin") {
		cfg.DecoyStyle = "directadmin"
	} else {
		cfg.DecoyStyle = "apache"
	}

	color.HiWhite("\n[INFO] Provisioning Summary:")
	labels := make([]string, len(mimicList))
	for i, m := range mimicList {
		labels[i] = fmt.Sprintf("%s:%d", m.Type, m.Port)
	}
	fmt.Printf(" - Mimics:     %s\n", strings.Join(labels, ", "))
	fmt.Printf(" - Auth Token: %s\n", color.HiYellowString(cfg.AuthToken))
	color.HiRed("   (CRITICAL: Retain this token for Iran Hub configuration)\n")
}

func setupIranNode(cfg *config.AppConfig, isFirstTime bool) {
	color.HiBlue("\n--- Egress Target Registration ---")

	node := config.ForeignNode{}
	suggestedSocksPort := getNextFreeSocksPort(cfg)

	questions := []*survey.Question{
		{
			Name:     "alias",
			Prompt:   &survey.Input{Message: "Server Alias (e.g., DE-Frankfurt-01):"},
			Validate: survey.Required,
		},
		{
			Name:     "targetip",
			Prompt:   &survey.Input{Message: "Foreign Egress IP (IPv4 or IPv6) or hostname:"},
			Validate: validateHost,
		},
		{
			Name:     "targetport",
			Prompt:   &survey.Input{Message: "Foreign SSH mimic port (other mimics use standard ports):", Default: "22"},
			Validate: validatePortInput,
		},
		{
			Name:     "localsocksport",
			Prompt:   &survey.Input{Message: "Local SOCKS5 Bind Port (for X-UI Outbound mapping):", Default: suggestedSocksPort},
			Validate: validatePortInput,
		},
		{
			Name:   "minconnections",
			Prompt: &survey.Input{Message: "Min Physical Connections (Warm-up pool baseline):", Default: "10"},
		},
		{
			Name:   "maxconnections",
			Prompt: &survey.Input{Message: "Max Physical Connections (Scale limit):", Default: "20"},
		},
		{
			Name:   "bandwidthlimit",
			Prompt: &survey.Input{Message: "Target Bandwidth Limit per Connection (Mbps):", Default: "8"},
		},
		{
			Name:   "bandwidthjitter",
			Prompt: &survey.Input{Message: "Bandwidth Jitter/Variance for DPI Evasion (Mbps):", Default: "2"},
		},
		{
			Name:     "authtoken",
			Prompt:   &survey.Input{Message: "Pairing token from the egress server (carries IP/ports/persona; a legacy auth token also works):"},
			Validate: survey.Required,
		},
	}

	answers := struct {
		Alias           string
		TargetIP        string
		TargetPort      string
		LocalSocksPort  string
		MinConnections  string
		MaxConnections  string
		BandwidthLimit  string
		BandwidthJitter string
		AuthToken       string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return
	}

	node.Alias = answers.Alias
	node.TargetIP = answers.TargetIP
	node.AuthToken = answers.AuthToken

	// A v2 pairing token is self-contained: it overrides the IP and endpoint set, so
	// the operator only has to paste it (the IP prompt above is ignored).
	fromToken := false
	if pt, isV2, err := pairing.Decode(strings.TrimSpace(answers.AuthToken)); err == nil && isV2 {
		fromToken = true
		node.TargetIP = pt.ExitIP
		node.AuthToken = pt.AuthKey
		for _, ty := range mimicTypesAll {
			if port, ok := pt.Endpoints[ty]; ok {
				sni := ""
				if ty != "ssh" {
					sni = pt.SNI
				}
				node.Endpoints = append(node.Endpoints, config.Endpoint{
					Target: net.JoinHostPort(pt.ExitIP, strconv.Itoa(port)), Mimic: ty, ServerName: sni,
				})
			}
		}
		label := pt.Persona
		if label == "" {
			label = "custom"
		}
		color.Green("[✓] Pairing token: %s persona, %d endpoints @ %s", label, len(node.Endpoints), pt.ExitIP)
	}

	// Safely parse all integer inputs, falling back to defaults if empty or invalid (0)
	node.TargetPort = clampPort(answers.TargetPort, 22)
	node.LocalSocksPort = clampPort(answers.LocalSocksPort, clampPort(suggestedSocksPort, socksPortBase))
	node.MinConnections = safeAtoi(answers.MinConnections, 10)
	node.MaxConnections = safeAtoi(answers.MaxConnections, 20)
	node.BandwidthLimitMbps = safeAtoi(answers.BandwidthLimit, 8)
	node.BandwidthJitterMbps = safeAtoi(answers.BandwidthJitter, 2)

	// Which mimics to reach this node over — must match what the foreign runs. A v2
	// pairing token already populated the endpoints above; otherwise, since the
	// persona is deterministic from the token, "auto" derives the exact set the
	// foreign chose; or match a named persona, or pick manually.
	var mimicTypes []string
	if !fromToken {
		hubPersonaChoice := ""
		survey.AskOne(&survey.Select{
			Message: "Match the foreign's mimic set (tip: paste the v2 pairing token instead to skip this):",
			Options: append([]string{"auto (from token)"}, append(persona.Names(), "custom (choose mimics)")...),
			Default: "auto (from token)",
			Help:    "auto matches an auto-configured foreign (same token → same persona). If the foreign FORCED a persona, choose that name here, or use the pairing token.",
		}, &hubPersonaChoice)
		if strings.HasPrefix(hubPersonaChoice, "custom") {
			mimicTypes = promptMimics()
		} else {
			name := strings.Fields(hubPersonaChoice)[0]
			if name == "auto" {
				name = persona.Auto(node.AuthToken)
			}
			if types, err := persona.Resolve(name, node.AuthToken); err == nil {
				mimicTypes = types
				color.Green("[✓] Persona %q → %d endpoints", name, len(types))
			} else {
				mimicTypes = promptMimics()
			}
		}
	}
	// Populating Endpoints is what enables the multi-mimic arsenal — without it the
	// node falls back to a single synthesized SSH endpoint.
	for _, ty := range mimicTypes {
		node.Endpoints = append(node.Endpoints, config.Endpoint{
			Target: net.JoinHostPort(node.TargetIP, strconv.Itoa(mimicPort(ty, node.TargetPort))),
			Mimic:  ty,
		})
	}
	color.Green("[✓] Endpoints: %d mimic(s) toward %s", len(node.Endpoints), node.TargetIP)

	// Optional TUN mode: expose this node as an OS-level interface too, so it can be
	// used by policy routing / a downstream router — not just as a SOCKS proxy. It is
	// opt-in and never becomes the host default route.
	enableTun := false
	survey.AskOne(&survey.Confirm{
		Message: "Also expose this node as a TUN network interface? (advanced; SOCKS always stays on)",
		Default: false,
		Help:    "Adds a virtual interface (e.g. hedioum0 @ 10.200.0.1/24) whose traffic egresses through this node. Leave off for a plain SOCKS-only node.",
	}, &enableTun)
	if enableTun {
		autoName, autoAddr := nextFreeTun(cfg)
		tunName := autoName
		survey.AskOne(&survey.Input{Message: "TUN interface name:", Default: autoName}, &tunName)
		tunAddr := autoAddr
		survey.AskOne(&survey.Input{
			Message: "TUN gateway CIDR:", Default: autoAddr,
			Help: "The .1 host becomes this node's gateway IP; the /24 must not overlap the hub's existing LANs.",
		}, &tunAddr)
		if _, _, err := net.ParseCIDR(tunAddr); err != nil {
			color.Yellow("[!] %q is not a valid CIDR; falling back to %s", tunAddr, autoAddr)
			tunAddr = autoAddr
		}
		enableDNS := false
		survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Run a DNS forwarder on %s:53 (resolves through the tunnel)?", tunGatewayIP(tunAddr)),
			Default: false,
			Help:    "For gateway/router clients that need a leak-free resolver on the tunnel's own address.",
		}, &enableDNS)
		node.TunEnabled = true
		node.TunName = tunName
		node.TunAddr = tunAddr
		node.DNSEnabled = enableDNS
		color.Green("[✓] TUN mode: %s @ %s (gateway %s)", tunName, tunAddr, tunGatewayIP(tunAddr))
		if enableDNS {
			color.Green("[✓] DNS forwarder: %s:53", tunGatewayIP(tunAddr))
		}

		// Gateway mode: make this a transparent L3 gateway (for MikroTik/router use).
		enableGW := false
		survey.AskOne(&survey.Confirm{
			Message: "Transparent gateway mode? (forward LAN transit into the tunnel — for MikroTik/router)",
			Default: false,
			Help:    "Turns this node into a WireGuard-like egress interface: the router marks traffic and routes it here. Off = TUN/SOCKS only.",
		}, &enableGW)
		if enableGW {
			node.GatewayEnabled = true
			color.Green("[✓] Gateway mode: forwarding transit from the LAN interface (auto: eth0) into the tunnel")
			color.HiBlack("    On the router: mark traffic and route it to this node's veth IP (see docs/MIKROTIK.md).")
		}
	}

	cfg.UpdateForeignNode(node)
}

// --- Helper Functions ---

// socksPortBase is where SOCKS5 port suggestions start.
const socksPortBase = 40001

// getNextFreeSocksPort suggests the next SOCKS5 port: one above the highest valid
// port already in use, skipping ports that are taken in config or busy on the OS.
// The search is bounded (it wraps to socksPortBase at 65535) so an out-of-range
// port in an existing node can never make it spin forever (issue #37).
func getNextFreeSocksPort(cfg *config.AppConfig) string {
	used := map[int]bool{}
	start := socksPortBase
	for _, node := range cfg.ForeignNodes {
		p := node.LocalSocksPort
		if validPort(p) != nil {
			continue // ignore a corrupt/out-of-range port instead of building on it
		}
		used[p] = true
		if p >= start && p < 65535 {
			start = p + 1
		}
	}

	free := func(p int) bool {
		if used[p] {
			return false
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return false
		}
		ln.Close()
		return true
	}
	for p := start; p <= 65535; p++ {
		if free(p) {
			return strconv.Itoa(p)
		}
	}
	for p := socksPortBase; p < start; p++ {
		if free(p) {
			return strconv.Itoa(p)
		}
	}
	return strconv.Itoa(socksPortBase) // nothing free in range; the operator can override
}

// validatePortInput is a survey validator for a port prompt (blank = use default).
func validatePortInput(val interface{}) error {
	s := strings.TrimSpace(fmt.Sprint(val))
	if s == "" {
		return nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%q is not a number", s)
	}
	return validPort(p)
}

// nextFreeTun assigns this hub's next unused TUN interface name and /24, so multiple
// foreign nodes each get a distinct interface + subnet (hedioum0/10.200.0.1/24,
// hedioum1/10.200.1.1/24, ...) and never collide with each other OR with the hub's
// existing LAN/interface subnets. The .1 host is the node's gateway IP. The range is
// hub-local only (the foreign never sees it); it is still overridable at setup.
func nextFreeTun(cfg *config.AppConfig) (name, addr string) {
	used := map[int]bool{}
	for _, n := range cfg.ForeignNodes {
		var idx int
		if _, err := fmt.Sscanf(n.TunName, "hedioum%d", &idx); err == nil {
			used[idx] = true
		}
	}
	// Avoid overlapping any subnet already present on this host.
	var local []*net.IPNet
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				local = append(local, ipnet)
			}
		}
	}
	conflicts := func(i int) bool {
		gw := net.IPv4(10, 200, byte(i), 1)
		for _, ln := range local {
			if ln.Contains(gw) {
				return true
			}
		}
		return false
	}
	for idx := 0; idx < 250; idx++ {
		if !used[idx] && !conflicts(idx) {
			return fmt.Sprintf("hedioum%d", idx), fmt.Sprintf("10.200.%d.1/24", idx)
		}
	}
	return "hedioum0", "10.200.0.1/24" // fallback (extremely unlikely to be reached)
}

// tunGatewayIP returns the bare gateway IP (10.200.N.1) from a TunAddr CIDR.
func tunGatewayIP(tunAddr string) string {
	if i := strings.IndexByte(tunAddr, '/'); i > 0 {
		return tunAddr[:i]
	}
	return tunAddr
}

// validateHost accepts a non-empty IPv4/IPv6 literal or a plausible hostname.
func validateHost(val interface{}) error {
	s, _ := val.(string)
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("a value is required")
	}
	if net.ParseIP(s) != nil {
		return nil // valid IPv4 or IPv6 literal
	}
	if strings.ContainsAny(s, " \t/\\") {
		return fmt.Errorf("not a valid IP or hostname")
	}
	return nil
}

// clampPort parses a port string, returning def if it is empty/invalid/out of range.
func clampPort(s string, def int) int {
	p := safeAtoi(s, def)
	if validPort(p) != nil {
		return def
	}
	return p
}

// safeAtoi parses strings to integers securely. It falls back to a provided default value
// if the input is empty, invalid, or zero (to prevent zero-port configuration bugs).
func safeAtoi(s string, defaultVal int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil || val <= 0 { // Also prevents negative values and 0
		return defaultVal
	}
	return val
}

// allMimics is the full camouflage arsenal, in the order the wizard offers it.
// Shared with the CLI (mimicTypesAll) so the two never disagree on the set.
var allMimics = mimicTypesAll

// promptMimics shows a checkbox selection of camouflage protocols and returns the
// chosen types, defaulting to ssh+tls. The first option ("all") selects the whole
// arsenal. Never returns empty (falls back to ssh+tls).
func promptMimics() []string { return promptMimicsWithDefault([]string{"ssh", "tls"}) }

// promptMimicsWithDefault is promptMimics with a caller-supplied pre-selection (used
// by the edit flows so the current mimic set is pre-checked). Never returns empty.
func promptMimicsWithDefault(def []string) []string {
	const allOpt = "all (enable every mimic)"
	if len(def) == 0 {
		def = []string{"ssh", "tls"}
	}
	var sel []string
	survey.AskOne(&survey.MultiSelect{
		Message: "Select camouflage protocols (Space toggles, Enter confirms):",
		Options: append([]string{allOpt}, allMimics...),
		Default: def,
		Help:    "ssh=22, tls=HTTPS:443, https-alt=8443, smtp=587, imap=143, smtps=465, imaps=993, directadmin=2222, docker=5000, grafana=3000, prometheus=9090, cpanel=2083, whm=2087, webmail=2096, postgres=5432, mysql=3306. Run several for a stronger, shifting signature.",
	}, &sel)

	chosen := map[string]bool{}
	for _, s := range sel {
		if s == allOpt {
			return append([]string{}, allMimics...)
		}
		chosen[s] = true
	}
	var out []string
	for _, t := range allMimics {
		if chosen[t] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		out = []string{"ssh", "tls"} // never leave a node with no camouflage
	}
	return out
}

// mimicPort maps a mimic type to its conventional port; the SSH port is caller-set
// so the operator can relocate it when outbound :22 is blocked.
func mimicPort(ty string, sshPort int) int {
	if ty == "ssh" {
		return sshPort
	}
	return conventionalPorts()[ty] // 0 for an unknown type
}

// containsStr reports whether s is in list.
func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
