package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

// wizardCancelled is raised by ask when the operator presses Ctrl+C inside a multi-prompt
// wizard, so the whole wizard stops (nothing is saved) instead of the keypress being
// swallowed and the next prompt appearing.
type wizardCancelled struct{}

var wizardDepth int

// ask is survey.AskOne that cancels the running wizard on Ctrl+C. Outside a cancellable
// wizard it behaves like survey.AskOne.
func ask(p survey.Prompt, resp interface{}, opts ...survey.AskOpt) {
	if err := survey.AskOne(p, resp, opts...); err == terminal.InterruptErr && wizardDepth > 0 {
		panic(wizardCancelled{})
	}
}

// cancellable runs a wizard and reports whether the operator cancelled it with Ctrl+C.
func cancellable(fn func()) (cancelled bool) {
	wizardDepth++
	defer func() {
		wizardDepth--
		if r := recover(); r != nil {
			if _, ok := r.(wizardCancelled); ok {
				cancelled = true
				return
			}
			panic(r)
		}
	}()
	fn()
	return false
}

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
	ask(&survey.Input{Message: msg, Default: strconv.Itoa(def)}, &s)
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

// promptPortDefault is promptIntDefault for a port: it re-asks until the value is
// within 1..65535 (blank keeps the default).
func promptPortDefault(msg string, def int) int {
	s := strconv.Itoa(def)
	ask(&survey.Input{Message: msg, Default: s}, &s, survey.WithValidator(validatePortInput))
	return clampPort(s, def)
}

func promptStrDefault(msg, def string) string {
	v := def
	ask(&survey.Input{Message: msg, Default: def}, &v)
	return strings.TrimSpace(v)
}

func selectDefault(msg string, opts []string, def string) string {
	var v string
	ask(&survey.Select{Message: msg, Options: opts, Default: def}, &v)
	if v == "" {
		return def
	}
	return v
}

// promptTokenChange asks whether to rotate the auth token; keeps the current one on No.
func promptTokenChange(current string) (string, bool) {
	change := false
	ask(&survey.Confirm{Message: "Change (rotate) the auth token?", Default: false}, &change)
	if !change {
		return current, false
	}
	return sysutil.GenerateSecureToken(), true
}

// editIranNode re-asks each add-node question for an existing node, pre-filled with
// its current values, and updates it in place.
func editIranNode(cfg *config.AppConfig, node config.ForeignNode) (restarted bool) {
	color.HiBlue("\n--- Edit Node %q (press Enter to keep the current value) ---\n", node.Alias)
	if node.Reverse {
		return editReverseIranNode(cfg, node)
	}
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

	n := nodeWithCommonEdits(node, socks, minC, maxC, bw, jit, tok)
	n.Endpoints = buildEndpoints(ip, types, portMap, sni)
	cfg.UpdateForeignNode(n)
	color.Green("[✓] Node %q updated (target %s, mimics: %s).", node.Alias, ip, strings.Join(types, ","))
	return false
}

// nodeWithCommonEdits returns the node with the settings both modes share changed and
// every other field (reverse listeners, front proxy, sharing...) left exactly as it was.
func nodeWithCommonEdits(node config.ForeignNode, socks, minC, maxC, bw, jit int, tok string) config.ForeignNode {
	node.LocalSocksPort = socks
	node.MinConnections = minC
	node.MaxConnections = maxC
	node.BandwidthLimitMbps = bw
	node.BandwidthJitterMbps = jit
	node.AuthToken = tok
	return node
}

// editReverseIranNode edits a node that is in reverse mode. The foreign's address,
// mimic types and ports do not apply (the foreign dials the hub), so they are not asked.
// The settings that do apply (SOCKS port, speed cap, token, then listener ports, SNI,
// decoy, front proxy and pipes) are all here. It reports whether it already saved and
// restarted the service. Switching between normal and reverse stays in its own entry.
func editReverseIranNode(cfg *config.AppConfig, node config.ForeignNode) (restarted bool) {
	color.HiCyan("This node is in REVERSE mode: the foreign dials this hub, so the foreign's address, mimics")
	color.HiCyan("and ports are not used. Current reverse settings:")
	printReverseSummary(node)
	fmt.Println()
	socks := promptPortDefault("Local SOCKS5 bind port:", node.LocalSocksPort)
	bw := promptIntDefault("Per-connection Mbps cap:", node.BandwidthLimitMbps)
	jit := promptIntDefault("Bandwidth jitter Mbps:", node.BandwidthJitterMbps)
	tok, changed := promptTokenChange(node.AuthToken)
	if changed {
		color.Yellow("[!] New token: %s — update the foreign server to match.", tok)
	}
	cfg.UpdateForeignNode(nodeWithCommonEdits(node, socks, node.MinConnections, node.MaxConnections, bw, jit, tok))

	var more bool
	ask(&survey.Confirm{Message: "Change the reverse settings too (listener ports, SNI, decoy, front proxy, pipes)?", Default: false}, &more)
	if !more {
		return false
	}
	before := commitCount
	reverseNodeFlow(cfg, node.Alias, true)
	return commitCount != before
}

// printReverseSummary prints what a reverse node is configured with.
func printReverseSummary(n config.ForeignNode) {
	for _, l := range n.ReverseListeners {
		fmt.Printf("  listener   %-10s port %d\n", l.Type, l.Port)
	}
	if len(n.ReverseListeners) > 0 && n.ReverseListeners[0].ServerName != "" {
		fmt.Printf("  SNI        %s\n", n.ReverseListeners[0].ServerName)
	}
	if n.ReverseBind != "" {
		fmt.Printf("  bind       %s\n", n.ReverseBind)
	}
	if n.ReverseProxyProtocol {
		fmt.Printf("  PROXY protocol required\n")
	}
	for ty, p := range n.ReverseAdvertise {
		fmt.Printf("  the foreign dials %s on port %d (front proxy)\n", ty, p)
	}
	if n.ReverseShareWith != "" {
		fmt.Printf("  shares the listener of %q\n", n.ReverseShareWith)
	}
	if n.ReverseDecoyStyle != "" {
		fmt.Printf("  decoy      %s\n", n.ReverseDecoyStyle)
	}
	if n.MinConnections > 0 {
		fmt.Printf("  pipes      %d-%d\n", n.MinConnections, n.MaxConnections)
	}
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
