package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// Advanced settings menus (hub and foreign). They gather the options that most users
// never need - sharing a port such as 443 with nginx / HAProxy, shared reverse
// listeners, several hubs - behind one entry each, using the same apply functions as
// the commands. Nothing here changes unless the operator picks it.

// setNodeBehindProxy points a normal-mode node at a front proxy: the hub dials the
// proxy's public port and sends the SNI the proxy routes on. Only that mimic's endpoint
// changes. It returns the endpoint host for the confirmation message.
func setNodeBehindProxy(node *config.ForeignNode, mimicType string, publicPort int, sni string) error {
	if node.Reverse {
		return fmt.Errorf("node %q is in reverse mode; use the Reverse Tunnel menu for its proxy settings", node.Alias)
	}
	if mimicType == "ssh" {
		return fmt.Errorf("the ssh mimic cannot be routed by SNI")
	}
	if err := validPort(publicPort); err != nil {
		return err
	}
	if sni == "" {
		return fmt.Errorf("an SNI is required: a front proxy routes the tunnel by it")
	}
	for i := range node.Endpoints {
		ep := &node.Endpoints[i]
		if ep.Mimic != mimicType {
			continue
		}
		host, _, err := net.SplitHostPort(ep.Target)
		if err != nil {
			return fmt.Errorf("endpoint %q is malformed: %v", ep.Target, err)
		}
		ep.Target = net.JoinHostPort(host, strconv.Itoa(publicPort))
		ep.ServerName = sni
		return nil
	}
	return fmt.Errorf("node %q has no %s endpoint", node.Alias, mimicType)
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

// nodeBehindProxy reports whether a normal node looks like it dials a proxy: an SNI is
// set and the port is not the mimic's conventional one.
func nodeBehindProxy(n config.ForeignNode) bool {
	conv := conventionalPorts()
	for _, ep := range n.Endpoints {
		if ep.Mimic == "ssh" || ep.ServerName == "" {
			continue
		}
		if _, ps, err := net.SplitHostPort(ep.Target); err == nil {
			if p, err := strconv.Atoi(ps); err == nil && conv[ep.Mimic] != 0 && p != conv[ep.Mimic] {
				return true
			}
		}
	}
	return false
}

func countWhere(cfg *config.AppConfig, pred func(config.ForeignNode) bool) (n, of int) {
	for _, node := range cfg.ForeignNodes {
		of++
		if pred(node) {
			n++
		}
	}
	return n, of
}

// runHubAdvancedMenu is the hub's "Advanced Settings" entry. Every complex option has
// an ON/OFF state shown in its label and is configured here, not only by command.
func runHubAdvancedMenu(cfg *config.AppConfig) {
	for {
		fwdOn, _ := countWhere(cfg, func(n config.ForeignNode) bool { return !n.Reverse && nodeBehindProxy(n) })
		revOn, _ := countWhere(cfg, func(n config.ForeignNode) bool { return n.Reverse && len(n.ReverseAdvertise) > 0 })
		optNormal := fmt.Sprintf("Front proxy (nginx / HAProxy) for normal nodes   [%d node(s) behind a proxy]", fwdOn)
		optReverse := fmt.Sprintf("[Hub side] Front proxy (nginx / HAProxy) for reverse nodes  [%d node(s) behind a proxy]", revOn)
		optShared := fmt.Sprintf("[Hub side] Shared reverse listener (several foreign servers on one SNI)   [%s]", onOff(cfg.SharedReverseAuth))
		optRevCfg := "[Hub side] Reverse nodes: ports, SNI, decoy, pipes, front proxy of a node"
		var choice string
		if err := survey.AskOne(&survey.Select{
			Message: "Advanced settings (everything here is off unless you turn it on):",
			Options: []string{optRevCfg, optNormal, optReverse, optShared, "Back"},
		}, &choice); err != nil || choice == "Back" {
			return
		}
		switch choice {
		case optRevCfg:
			runReverseIranAdvanced(cfg)
		case optNormal:
			hubProxyForwardNode(cfg)
		case optReverse:
			hubProxyReverseNode(cfg)
		case optShared:
			runSharedAuthMenu(cfg)
		}
	}
}

func nodesWhere(cfg *config.AppConfig, pred func(config.ForeignNode) bool) []string {
	var out []string
	for _, n := range cfg.ForeignNodes {
		if pred(n) {
			out = append(out, n.Alias)
		}
	}
	return out
}

// hubProxyForwardNode turns the front-proxy setting of a normal node ON (it dials the
// proxy's port with an SNI) or OFF (it dials the mimic's own port again).
func hubProxyForwardNode(cfg *config.AppConfig) {
	var labels []string
	byLabel := map[string]string{}
	for _, n := range cfg.ForeignNodes {
		if n.Reverse {
			continue
		}
		l := fmt.Sprintf("%s   [%s]", n.Alias, onOff(nodeBehindProxy(n)))
		labels = append(labels, l)
		byLabel[l] = n.Alias
	}
	if len(labels) == 0 {
		color.Yellow("\n[!] No normal-mode nodes. (Reverse nodes are in the next entry.)")
		return
	}
	var picked string
	if err := survey.AskOne(&survey.Select{Message: "Which node's foreign sits behind a proxy?", Options: labels}, &picked); err != nil {
		return
	}
	alias := byLabel[picked]
	node := findNode(cfg, alias)
	var types []string
	for _, ep := range node.Endpoints {
		if ep.Mimic != "ssh" {
			types = append(types, ep.Mimic)
		}
	}
	if len(types) == 0 {
		color.Red("[x] The node has no TLS mimic; enable one first (Edit Existing Egress Node).")
		return
	}
	ty := types[0]
	if len(types) > 1 {
		_ = survey.AskOne(&survey.Select{Message: "A proxy routes one SNI to one listener. Which mimic?", Options: types}, &ty)
	}
	var act string
	_ = survey.AskOne(&survey.Select{Message: "Front proxy for " + alias + ":", Options: []string{"Turn ON (dial the proxy's port with an SNI)", "Turn OFF (dial the mimic's own port, no SNI routing)", "Cancel"}}, &act)
	switch {
	case strings.HasPrefix(act, "Turn ON"):
		cur := currentNodePorts(*node)[ty]
		port, ok := askInt("Port the proxy listens on at the foreign (what this hub dials):", 443)
		if !ok {
			return
		}
		sni := strings.TrimSpace(promptStrDefault("SNI that identifies the tunnel at the proxy:", firstEndpointSNI(*node)))
		if err := setNodeBehindProxy(node, ty, port, sni); err != nil {
			color.Red("[x] %v", err)
			return
		}
		color.Green("[✓] Node %q now dials %s on port %d with SNI %q (was port %d).", alias, ty, port, sni, cur)
		commitReverse(cfg)
		color.HiCyan("\nNow set the matching side on the foreign: its menu, Advanced Settings -> Front proxy.")
		color.White("Do the foreign and nginx first; until they are ready this node cannot connect.")
	case strings.HasPrefix(act, "Turn OFF"):
		port, ok := askInt("Port the foreign's tunnel listens on directly:", conventionalPorts()[ty])
		if !ok {
			return
		}
		if err := setNodeBehindProxy(node, ty, port, "-"); err != nil {
			color.Red("[x] %v", err)
			return
		}
		for i := range node.Endpoints {
			if node.Endpoints[i].Mimic == ty {
				node.Endpoints[i].ServerName = ""
			}
		}
		color.Green("[✓] Node %q dials %s on port %d directly again.", alias, ty, port)
		commitReverse(cfg)
	}
}

// hubProxyReverseNode turns the front-proxy setting of a reverse node ON or OFF, or
// shows the nginx / HAProxy configuration for it.
func hubProxyReverseNode(cfg *config.AppConfig) {
	var labels []string
	byLabel := map[string]string{}
	for _, n := range cfg.ForeignNodes {
		if !n.Reverse {
			continue
		}
		l := fmt.Sprintf("%s   [%s]", n.Alias, onOff(len(n.ReverseAdvertise) > 0))
		labels = append(labels, l)
		byLabel[l] = n.Alias
	}
	if len(labels) == 0 {
		color.Yellow("\n[!] No reverse nodes yet. Switch one in the Reverse Tunnel menu first.")
		return
	}
	var picked string
	if err := survey.AskOne(&survey.Select{Message: "Which reverse node?", Options: labels}, &picked); err != nil {
		return
	}
	alias := byLabel[picked]
	node := findNode(cfg, alias)
	var act string
	_ = survey.AskOne(&survey.Select{Message: "Front proxy for " + alias + ":", Options: []string{
		"Turn ON / change (guided)", "Turn OFF (the foreign dials the listener ports directly)", "Show the nginx / HAProxy config", "Cancel",
	}}, &act)
	switch {
	case strings.HasPrefix(act, "Turn ON"):
		var opts reverseOpts
		askFrontProxy(cfg, node, nil, &opts)
		plan, tok, err := applyReverseIran(cfg, alias, nil, "", opts)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		printReversePlan(alias, plan)
		commitReverse(cfg)
		if len(node.ReverseAdvertise) > 0 {
			color.HiCyan("\n━━━ Add this to nginx / HAProxy first ━━━")
			showFrontProxyConfig(findNode(cfg, alias))
		}
		color.HiGreen("\n━━━ Run this on the foreign server now ━━━")
		fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)
	case strings.HasPrefix(act, "Turn OFF"):
		empty, pp := "", false
		opts := reverseOpts{AdvertiseSet: true, Bind: &empty, ProxyProtocol: &pp}
		plan, tok, err := applyReverseIran(cfg, alias, nil, "", opts)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		printReversePlan(alias, plan)
		commitReverse(cfg)
		color.HiGreen("\n━━━ Run this on the foreign server now (it must dial the listener ports) ━━━")
		fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)
	case strings.HasPrefix(act, "Show"):
		hubProxyConfigForReverse(cfg, node)
	}
}

// hubProxyConfigForReverse prints the proxy config for a reverse node, optionally
// routed by the foreign's source IP so the tunnel can share an SNI with a real service.
func hubProxyConfigForReverse(cfg *config.AppConfig, node *config.ForeignNode) {
	up, sni, err := frontProxyUpstream(*node)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	sp := frontSpec{Upstream: up, SNI: sni, ProxyProtocol: node.ReverseProxyProtocol}
	var bySource bool
	_ = survey.AskOne(&survey.Confirm{
		Message: "Share an SNI with a real service? (route the foreign servers by their IP instead of the SNI)",
		Default: false,
	}, &bySource)
	if bySource {
		sp.Sources = nodeSourceIPs(cfg, *node)
		if len(sp.Sources) == 0 {
			color.Red("[x] This node has no foreign IP on record; use: hedioum-tunnel front-proxy --alias %s --source-ips IP,IP", node.Alias)
			return
		}
	}
	fmt.Println()
	fmt.Println(nginxFor(sp, 443))
	fmt.Println(haproxyFor(sp, 443))
}

// foreignProxyOn reports whether any front-proxy setting is active on a foreign.
func foreignProxyOn(cfg *config.AppConfig) bool {
	return len(cfg.AdvertisePorts) > 0 || cfg.ListenBind != "" || cfg.ProxyProtocol
}

// runForeignAdvancedMenu is the foreign's "Advanced Settings" entry. Each option shows
// its ON/OFF state and is configured here.
func runForeignAdvancedMenu(cfg *config.AppConfig) {
	for {
		optProxy := fmt.Sprintf("Front proxy (nginx / HAProxy shares a port such as 443)   [%s]", onOff(foreignProxyOn(cfg)))
		optSource := "Share an SNI with a real service: proxy config routed by the hub's IP"
		optToken := "Pairing token for the hub (with the proxy's public port)"
		optHubs := fmt.Sprintf("[Foreign side] Reverse hubs: add another hub / pipe range / remove   [%d hub(s)]", len(cfg.EffectiveReverseHubs()))
		options := []string{optProxy, optSource, optToken}
		if len(cfg.ReverseTargets) > 0 {
			options = append(options, optHubs)
		}
		options = append(options, "Back")
		var choice string
		if err := survey.AskOne(&survey.Select{Message: "Advanced settings (everything here is off unless you turn it on):", Options: options}, &choice); err != nil || choice == "Back" {
			return
		}
		switch choice {
		case optProxy:
			runForeignFrontProxyMenu(cfg)
		case optSource:
			showForeignConfigBySource(cfg)
		case optToken:
			cmdPairingToken(nil)
		case optHubs:
			var act string
			_ = survey.AskOne(&survey.Select{Message: "Reverse hubs:", Options: []string{"Add another hub", "Show / change pipe range / remove", "Cancel"}}, &act)
			switch {
			case strings.HasPrefix(act, "Add"):
				addHubMenu(cfg)
			case strings.HasPrefix(act, "Show"):
				manageHubsMenu(cfg)
			}
		}
	}
}

// showForeignConfigBySource prints the proxy configuration that sends the hub's address
// to the tunnel whatever SNI it presents, so the tunnel can share an SNI with a real
// service. It only prints.
func showForeignConfigBySource(cfg *config.AppConfig) {
	sp, err := foreignFrontSpec(cfg)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	var spec string
	_ = survey.AskOne(&survey.Input{Message: "IP address(es) of the Iran hub, comma separated:"}, &spec)
	ips, err := parseSourceIPs(strings.TrimSpace(spec))
	if err != nil || len(ips) == 0 {
		color.Red("[x] Enter at least one exact IP address.")
		return
	}
	sp.Sources = ips
	var kind string
	_ = survey.AskOne(&survey.Select{Message: "Which proxy?", Options: []string{"nginx", "haproxy"}}, &kind)
	fmt.Println()
	if kind == "haproxy" {
		fmt.Println(haproxyFor(sp, 443))
	} else {
		fmt.Println(nginxFor(sp, 443))
	}
}
