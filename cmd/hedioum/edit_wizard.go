package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

// --- interactive edit helpers (every prompt pre-fills the current value; Enter keeps it) ---

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func promptIntDefault(msg string, def int) int {
	var s string
	survey.AskOne(&survey.Input{Message: msg, Default: strconv.Itoa(def)}, &s)
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

// promptPortDefault is promptIntDefault for a port: it re-asks until the value is
// within 1..65535 (blank keeps the default).
func promptPortDefault(msg string, def int) int {
	s := strconv.Itoa(def)
	survey.AskOne(&survey.Input{Message: msg, Default: s}, &s, survey.WithValidator(validatePortInput))
	return clampPort(s, def)
}

func promptStrDefault(msg, def string) string {
	v := def
	survey.AskOne(&survey.Input{Message: msg, Default: def}, &v)
	return strings.TrimSpace(v)
}

func selectDefault(msg string, opts []string, def string) string {
	var v string
	survey.AskOne(&survey.Select{Message: msg, Options: opts, Default: def}, &v)
	if v == "" {
		return def
	}
	return v
}

// promptTokenChange asks whether to rotate the auth token; keeps the current one on No.
func promptTokenChange(current string) (string, bool) {
	change := false
	survey.AskOne(&survey.Confirm{Message: "Change (rotate) the auth token?", Default: false}, &change)
	if !change {
		return current, false
	}
	return sysutil.GenerateSecureToken(), true
}

// editIranNode re-asks each add-node question for an existing node, pre-filled with
// its current values, and updates it in place.
func editIranNode(cfg *config.AppConfig, node config.ForeignNode) {
	color.HiBlue("\n--- Edit Node %q (press Enter to keep the current value) ---\n", node.Alias)
	ports := currentNodePorts(node)

	ip := promptStrDefault("Foreign Egress IP/host:", nodeTargetIP(node))
	types := promptMimicsWithDefault(splitCSV(nodeMimicTypesCSV(node)))
	portMap := currentNodePorts(node)
	for _, ty := range types {
		portMap[ty] = promptPortDefault(fmt.Sprintf("  %s port:", ty), ports[ty])
	}
	sni := promptStrDefault("TLS SNI (foreign domain; blank = none):", firstEndpointSNI(node))
	socks := promptPortDefault("Local SOCKS5 bind port:", node.LocalSocksPort)
	minC := promptIntDefault("Min warm-up connections:", node.MinConnections)
	maxC := promptIntDefault("Max connections:", node.MaxConnections)
	bw := promptIntDefault("Per-connection Mbps cap:", node.BandwidthLimitMbps)
	jit := promptIntDefault("Bandwidth jitter Mbps:", node.BandwidthJitterMbps)
	tok, changed := promptTokenChange(node.AuthToken)
	if changed {
		color.Yellow("[!] New token: %s — update the foreign server to match.", tok)
	}

	cfg.UpdateForeignNode(config.ForeignNode{
		Alias:               node.Alias,
		LocalSocksPort:      socks,
		AuthToken:           tok,
		Endpoints:           buildEndpoints(ip, types, portMap, sni),
		MinConnections:      minC,
		MaxConnections:      maxC,
		BandwidthLimitMbps:  bw,
		BandwidthJitterMbps: jit,
	})
	color.Green("[✓] Node %q updated (target %s, mimics: %s).", node.Alias, ip, strings.Join(types, ","))
}

// editForeignConfig re-asks each foreign setup question, pre-filled with the current
// values, and updates the config in place.
func editForeignConfig(cfg *config.AppConfig) {
	color.HiBlue("\n--- Edit Foreign Configuration (press Enter to keep the current value) ---\n")
	ports := currentForeignPorts(cfg)

	types := promptMimicsWithDefault(splitCSV(mimicTypesCSV(cfg.Mimics)))
	portMap := conventionalPorts()
	for _, ty := range types {
		portMap[ty] = promptIntDefault(fmt.Sprintf("  %s port:", ty), ports[ty])
	}
	decoyDefault := cfg.DecoyPort
	if decoyDefault == 0 {
		decoyDefault = 2022
	}
	decoyPort := decoyDefault
	if containsStr(types, "ssh") {
		decoyPort = promptIntDefault("Decoy sshd port:", decoyDefault)
	}
	sni := promptStrDefault("TLS SNI/CN (blank = none):", firstServerName(cfg.Mimics))
	domain := promptStrDefault("Domain for a real certificate (blank = self-signed):", cfg.Domain)
	email := cfg.ACMEEmail
	if domain != "" {
		email = promptStrDefault("Let's Encrypt account email (optional):", cfg.ACMEEmail)
	}
	styleDef := cfg.DecoyStyle
	if styleDef == "" {
		styleDef = "apache"
	}
	style := selectDefault("Decoy persona for unauthorized probes:", []string{"apache", "directadmin"}, styleDef)
	modeDef := cfg.EgressIPMode
	if modeDef == "" {
		modeDef = "ipv4"
	}
	mode := selectDefault("Egress IP mode:", []string{"ipv4", "ipv6", "dual"}, modeDef)
	tok, changed := promptTokenChange(cfg.AuthToken)
	if changed {
		color.Yellow("[!] New token: %s — update every Iran hub node that dials this server.", tok)
	}

	cfg.Mimics = buildForeignMimicList(types, portMap, decoyPort, sni)
	cfg.ForeignListenPort = portMap["ssh"]
	cfg.DecoyPort = decoyPort
	cfg.Domain = domain
	cfg.ACMEEmail = email
	cfg.DecoyStyle = style
	cfg.EgressIPMode = mode
	cfg.AuthToken = tok
	color.Green("[✓] Foreign configuration updated (mimics: %s, domain: %q, style: %s).", strings.Join(types, ","), domain, style)
}
