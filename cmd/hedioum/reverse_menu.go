package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// Interactive entries for the reverse tunnel switch (dashboard menu). They are a thin
// layer over the same plan/apply functions the `reverse-iran` / `reverse-foreign`
// commands use, so both paths behave identically.

// commitReverse saves the config and applies it to the running service.
func commitReverse(cfg *config.AppConfig) {
	if err := config.SaveConfig(cfg); err != nil {
		color.Red("[x] Failed to save config: %v", err)
		return
	}
	reconcileUnit(cfg.Role)
	restartDaemon()
	color.Green("[✓] Saved; service restarted.")
}

// nodeModeLabel is the menu/status tag of a hub node.
func nodeModeLabel(n config.ForeignNode) string {
	if n.Reverse {
		return "reverse"
	}
	return "normal"
}

// reverseDecoyChoice is the menu's default decoy: the node's, else the hub's.
func reverseDecoyChoice(cfg *config.AppConfig, node *config.ForeignNode) string {
	if node.ReverseDecoyStyle == "directadmin" || (node.ReverseDecoyStyle == "" && cfg.DecoyStyle == "directadmin") {
		return "directadmin"
	}
	return "apache"
}

// runReverseIranMenu flips one hub node between normal and reverse mode.
func runReverseIranMenu(cfg *config.AppConfig) {
	if len(cfg.ForeignNodes) == 0 {
		color.Yellow("\n[!] No egress nodes configured. Use Option 3 to add one.")
		return
	}
	byLabel := map[string]string{}
	var labels []string
	for _, n := range cfg.ForeignNodes {
		l := fmt.Sprintf("%s  [%s]", n.Alias, nodeModeLabel(n))
		labels = append(labels, l)
		byLabel[l] = n.Alias
	}
	const advancedLabel = "Advanced: shared listener (one SNI for several foreign servers)"
	labels = append(labels, advancedLabel)
	var picked string
	if err := survey.AskOne(&survey.Select{Message: "Which node to switch?", Options: labels}, &picked); err != nil {
		return
	}
	if picked == advancedLabel {
		runSharedAuthMenu(cfg)
		return
	}
	alias := byLabel[picked]
	node := findNode(cfg, alias)
	if node == nil {
		return
	}

	if node.Reverse {
		var choice string
		_ = survey.AskOne(&survey.Select{
			Message: fmt.Sprintf("Node %q is in reverse mode. What now?", alias),
			Options: []string{
				"Reconfigure (ports, SNI, front proxy)",
				"Show the nginx / HAProxy config for this node",
				"Switch back to the normal mode",
				"Cancel",
			},
		}, &choice)
		switch {
		case strings.HasPrefix(choice, "Show"):
			showFrontProxyConfig(node)
			return
		case strings.HasPrefix(choice, "Switch back"):
			if err := applyForwardIran(cfg, alias); err != nil {
				color.Red("[x] %v", err)
				return
			}
			commitReverse(cfg)
			color.Yellow("    Also switch the foreign back: hedioum-tunnel reverse-foreign --forward")
			return
		case strings.HasPrefix(choice, "Reconfigure"):
		default:
			return
		}
	}

	if len(node.ReverseListeners) > 0 {
		var quick string
		_ = survey.AskOne(&survey.Select{
			Message: fmt.Sprintf("Node %q was in reverse mode before. What now?", alias),
			Options: []string{
				"Switch to reverse again with the saved settings (one step)",
				"Reconfigure (ports, SNI, front proxy)",
				"Cancel",
			},
		}, &quick)
		switch {
		case strings.HasPrefix(quick, "Switch to reverse"):
			opts := reverseOpts{ShareWith: resumeShareWith(cfg, alias)}
			plan, tok, err := applyReverseIran(cfg, alias, nil, "", opts)
			if err != nil {
				color.Red("[x] %v", err)
				return
			}
			printReversePlan(alias, plan)
			commitReverse(cfg)
			color.HiGreen("\n━━━ On the foreign server ━━━")
			color.White("If it still has its reverse settings: hedioum-tunnel reverse-foreign --resume")
			color.White("Otherwise: hedioum-tunnel reverse-foreign --token %s", tok)
			return
		case strings.HasPrefix(quick, "Reconfigure"):
		default:
			return
		}
	}

	color.HiCyan("\nReverse mode: %q will keep its token and settings, but the foreign dials this hub.", alias)
	var overrides map[string]int
	var opts reverseOpts
	if joinShared(cfg, node, &opts) {
		plan, tok, err := applyReverseIran(cfg, alias, nil, "", opts)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		printReversePlan(alias, plan)
		commitReverse(cfg)
		color.HiGreen("\n━━━ Run this on the foreign server now ━━━")
		fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)
		return
	}
	for {
		plan, err := planReverse(cfg, node, overrides, opts.SNI)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		color.HiWhite("\nThe hub will listen on (must be reachable from the foreign):")
		for _, l := range plan.Listeners {
			note := ""
			if old, moved := plan.Moved[l.Type]; moved {
				note = fmt.Sprintf("   (port %d is taken on this host)", old)
			}
			fmt.Printf("  %-10s %d%s\n", l.Type, l.Port, note)
		}
		if plan.SNI != "" {
			fmt.Printf("  SNI        %s\n", plan.SNI)
		}
		var spec string
		_ = survey.AskOne(&survey.Input{
			Message: "Press Enter to accept, or type other ports (TYPE=PORT,...):",
		}, &spec)
		spec = strings.TrimSpace(spec)
		if spec == "" {
			break
		}
		o, perr := parsePortOverrides(spec)
		if perr != nil {
			color.Red("[x] %v", perr)
			continue
		}
		overrides = o
	}

	// Camouflage: mirror what the foreign wears (SNI it sends, decoy it shows).
	_ = survey.AskOne(&survey.Input{
		Message: "TLS SNI (the foreign's domain/SNI; Enter keeps the current one):",
		Default: opts.SNI,
	}, &opts.SNI)
	opts.SNI = strings.TrimSpace(opts.SNI)
	_ = survey.AskOne(&survey.Select{
		Message: "Decoy shown to unauthorized probes (match the foreign's decoy-style):",
		Options: []string{"apache", "directadmin"},
		Default: reverseDecoyChoice(cfg, node),
	}, &opts.Decoy)

	askFrontProxy(cfg, node, overrides, &opts)

	plan, tok, err := applyReverseIran(cfg, alias, overrides, "", opts)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	printReversePlan(alias, plan)
	commitReverse(cfg)
	if len(node.ReverseAdvertise) > 0 {
		color.HiCyan("\n━━━ Front proxy: add this to nginx / HAProxy first ━━━")
		showFrontProxyConfig(findNode(cfg, alias))
	}
	color.HiGreen("\n━━━ Run this on the foreign server now ━━━")
	fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)
	color.Yellow("(or choose \"Reverse Mode\" in the foreign's menu and paste the token)")
}

// reverseNodesOtherThan lists the reverse nodes a node could share a listener with.
func reverseNodesOtherThan(cfg *config.AppConfig, alias string) []string {
	var out []string
	for _, n := range cfg.ForeignNodes {
		if n.Reverse && n.Alias != alias && len(n.ReverseListeners) > 0 {
			out = append(out, n.Alias)
		}
	}
	return out
}

// joinShared offers to put the node on another reverse node's listener. It only asks
// when the advanced setting is on and there is a node to join; it reports whether the
// operator chose to share (opts.ShareWith is then set).
func joinShared(cfg *config.AppConfig, node *config.ForeignNode, opts *reverseOpts) bool {
	if !cfg.SharedReverseAuth {
		return false
	}
	others := reverseNodesOtherThan(cfg, node.Alias)
	if len(others) == 0 {
		return false
	}
	var share bool
	_ = survey.AskOne(&survey.Confirm{
		Message: "Put this node on the same listener / SNI as another reverse node (advanced)?",
		Default: false,
	}, &share)
	if !share {
		return false
	}
	var with string
	if err := survey.AskOne(&survey.Select{Message: "Share the listener of which node?", Options: others}, &with); err != nil {
		return false
	}
	opts.ShareWith = with
	return true
}

// runSharedAuthMenu turns the advanced shared-listener setting on or off.
func runSharedAuthMenu(cfg *config.AppConfig) {
	state := "OFF"
	if cfg.SharedReverseAuth {
		state = "ON"
	}
	color.HiCyan("\nShared reverse listeners are %s.", state)
	color.White("When on, several foreign servers can dial the same port and SNI (for example one SNI")
	color.White("behind nginx); the hub tells them apart by their node token. Leave it off unless you")
	color.White("need that: with it off every node has its own port.")
	for _, g := range sharedGroups(cfg) {
		color.White("  shared: %s", g)
	}
	want := !cfg.SharedReverseAuth
	var ok bool
	_ = survey.AskOne(&survey.Confirm{Message: fmt.Sprintf("Turn it %s?", map[bool]string{true: "ON", false: "OFF"}[want])}, &ok)
	if !ok {
		return
	}
	if err := setSharedReverseAuth(cfg, want); err != nil {
		color.Red("[x] %v", err)
		return
	}
	commitReverse(cfg)
	if want {
		color.Yellow("    Now pick a node and choose to share another node's listener.")
	}
}

// runReverseForeignMenu switches the foreign to dial the hub, or back.
func runReverseForeignMenu(cfg *config.AppConfig) {
	inReverse := len(cfg.ReverseTargets) > 0
	if !inReverse && cfg.ReverseSaved != nil && (len(cfg.ReverseSaved.Targets) > 0 || len(cfg.ReverseSaved.Hubs) > 0) {
		var resume bool
		_ = survey.AskOne(&survey.Confirm{
			Message: "This foreign was in reverse mode before. Switch back to it with the saved settings (no token)?",
			Default: true,
		}, &resume)
		if resume {
			if err := applyResumeForeign(cfg); err != nil {
				color.Red("[x] %v", err)
				return
			}
			commitReverse(cfg)
			color.Yellow("    Make sure the hub node is in reverse mode too.")
			return
		}
	}
	if inReverse {
		color.HiCyan("\nThis foreign is in REVERSE mode (it dials the hub, %d endpoint(s)).", len(cfg.ReverseTargets))
		var choice string
		_ = survey.AskOne(&survey.Select{
			Message: "What now?",
			Options: []string{"Add another hub (dial a second Iran server)", "Hubs: show / change pipe range / remove", "Switch back to the normal mode", "Paste a new reverse token", "Cancel"},
		}, &choice)
		switch {
		case strings.HasPrefix(choice, "Add another"):
			addHubMenu(cfg)
			return
		case strings.HasPrefix(choice, "Hubs:"):
			manageHubsMenu(cfg)
			return
		case strings.HasPrefix(choice, "Switch back"):
			if err := applyForwardForeign(cfg); err != nil {
				color.Red("[x] %v", err)
				return
			}
			commitReverse(cfg)
			color.Yellow("    Also on the hub: switch the node back to the normal mode.")
			return
		case strings.HasPrefix(choice, "Paste"):
		default:
			return
		}
	}

	var token string
	if err := survey.AskOne(&survey.Input{Message: "Reverse token from the hub (hedioum-tunnel reverse-foreign --token ...):"}, &token); err != nil {
		return
	}
	token = strings.TrimSpace(token)
	if i := strings.LastIndex(token, " "); i >= 0 { // accept the whole pasted command too
		token = token[i+1:]
	}
	if token == "" {
		return
	}
	connsStr := "12"
	_ = survey.AskOne(&survey.Input{Message: "Pipes to keep open to the hub:", Default: "12"}, &connsStr)
	conns, err := strconv.Atoi(strings.TrimSpace(connsStr))
	if err != nil || conns < 1 {
		color.Red("[x] Pipes must be a positive number.")
		return
	}
	keep := false
	_ = survey.AskOne(&survey.Confirm{
		Message: "Also keep the normal inbound listeners? (No = dial-out only, no open ports)",
		Default: false,
	}, &keep)

	n, keyChanged, err := applyReverseForeign(cfg, token, conns, keep)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	if keyChanged {
		color.Yellow("[!] The token's auth key differs from this foreign's: switched to the hub's key.")
	}
	color.Green("[✓] Reverse mode on: dialing the hub across %d endpoint(s).", n)
	commitReverse(cfg)
}

// pastedToken reads a pairing token from the prompt, accepting the whole pasted command.
func pastedToken(msg string) string {
	var token string
	if err := survey.AskOne(&survey.Input{Message: msg}, &token); err != nil {
		return ""
	}
	token = strings.TrimSpace(token)
	if i := strings.LastIndex(token, " "); i >= 0 {
		token = token[i+1:]
	}
	return token
}

func askInt(msg string, def int) (int, bool) {
	s := strconv.Itoa(def)
	if err := survey.AskOne(&survey.Input{Message: msg, Default: s}, &s); err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 {
		color.Red("[x] Enter a positive number.")
		return 0, false
	}
	return n, true
}

// addHubMenu makes the foreign dial one more hub.
func addHubMenu(cfg *config.AppConfig) {
	token := pastedToken("Reverse token from the other hub (reverse-iran on that hub):")
	if token == "" {
		return
	}
	var name string
	_ = survey.AskOne(&survey.Input{Message: "A label for this hub (Enter = its IP):"}, &name)
	min, ok := askInt("Pipes always kept open to this hub (minimum):", config.DefaultReverseConns)
	if !ok {
		return
	}
	max, ok := askInt("Most pipes under load (maximum; same as minimum = fixed):", config.SuggestedReverseMaxFor(min))
	if !ok {
		return
	}
	hub, err := applyAddHub(cfg, token, strings.TrimSpace(name), min, max, false)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	color.Green("[✓] Hub %q added: %s.", hub.Name, pipeRangeText(hub))
	color.Yellow("    Keep that hub node's max_connections at or above the maximum.")
	commitReverse(cfg)
}

// manageHubsMenu lists the hubs and lets the operator change a pipe range or remove one.
func manageHubsMenu(cfg *config.AppConfig) {
	hubs := cfg.EffectiveReverseHubs()
	if len(hubs) == 0 {
		return
	}
	var labels []string
	byLabel := map[string]string{}
	for _, h := range hubs {
		l := fmt.Sprintf("%s  [%s]", h.Name, pipeRangeText(h))
		labels = append(labels, l)
		byLabel[l] = h.Name
	}
	var picked string
	if err := survey.AskOne(&survey.Select{Message: "Which hub?", Options: labels}, &picked); err != nil {
		return
	}
	name := byLabel[picked]
	var act string
	_ = survey.AskOne(&survey.Select{Message: "Hub " + name, Options: []string{"Change pipe range", "Remove this hub", "Cancel"}}, &act)
	switch {
	case strings.HasPrefix(act, "Change"):
		cur := hubs[0]
		for _, h := range hubs {
			if h.Name == name {
				cur = h
			}
		}
		min, ok := askInt("Minimum pipes:", cur.MinConns)
		if !ok {
			return
		}
		suggest := cur.MaxConns
		if suggest <= cur.MinConns { // a fixed pool: propose the usual range instead of repeating the minimum
			suggest = config.SuggestedReverseMaxFor(cur.MinConns)
		}
		max, ok := askInt("Maximum pipes (the hub's max_connections for this node must be at least this):", suggest)
		if !ok {
			return
		}
		if err := applyEditHub(cfg, name, min, max); err != nil {
			color.Red("[x] %v", err)
			return
		}
		commitReverse(cfg)
	case strings.HasPrefix(act, "Remove"):
		if err := applyRemoveHub(cfg, name); err != nil {
			color.Red("[x] %v", err)
			return
		}
		commitReverse(cfg)
	}
}

// askFrontProxy asks whether an nginx / HAProxy sits in front of the public port and
// fills opts (advertised port, loopback bind, PROXY protocol) accordingly.
func askFrontProxy(cfg *config.AppConfig, node *config.ForeignNode, overrides map[string]int, opts *reverseOpts) {
	var how string
	_ = survey.AskOne(&survey.Select{
		Message: "How will the foreign reach this hub?",
		Options: []string{
			"Directly on the listener ports",
			"Through a reverse proxy (nginx / HAProxy) on a shared port such as 443",
		},
	}, &how)
	if !strings.HasPrefix(how, "Through") {
		// Direct: clear any earlier front-proxy settings.
		opts.AdvertiseSet = true
		empty, pp := "", false
		opts.Bind, opts.ProxyProtocol = &empty, &pp
		return
	}

	plan, err := planReverse(cfg, node, overrides, opts.SNI)
	if err != nil || len(plan.Listeners) == 0 {
		color.Red("[x] cannot plan the listeners: %v", err)
		return
	}
	ty := plan.Listeners[0].Type
	if len(plan.Listeners) > 1 {
		var types []string
		for _, l := range plan.Listeners {
			types = append(types, l.Type)
		}
		_ = survey.AskOne(&survey.Select{
			Message: "A proxy routes one SNI to one listener. Which mimic type should the foreign use?",
			Options: types,
		}, &ty)
	}
	portStr := "443"
	_ = survey.AskOne(&survey.Input{Message: "Public port the proxy listens on:", Default: "443"}, &portStr)
	port, perr := strconv.Atoi(strings.TrimSpace(portStr))
	if perr != nil || validPort(port) != nil {
		color.Red("[x] invalid port; keeping direct access")
		return
	}
	pp := false
	_ = survey.AskOne(&survey.Confirm{
		Message: "Does your proxy send the PROXY protocol? (nginx: `proxy_protocol on;` in the stream server)",
		Default: false,
	}, &pp)
	local := true
	_ = survey.AskOne(&survey.Confirm{
		Message: "Bind the hub listener to 127.0.0.1 so it is only reachable through the proxy?",
		Default: true,
	}, &local)
	bind := ""
	if local {
		bind = "127.0.0.1"
	}
	opts.Advertise = map[string]int{ty: port}
	opts.AdvertiseSet = true
	opts.Bind, opts.ProxyProtocol = &bind, &pp
	if opts.SNI == "" && plan.SNI == "" {
		color.Yellow("[!] A proxy routes by SNI: set one in the SNI prompt (a name that is not one of your sites).")
	}
}

// showFrontProxyConfig prints the nginx and HAProxy snippets for a node.
func showFrontProxyConfig(node *config.ForeignNode) {
	for _, gen := range []func(config.ForeignNode, int) (string, error){nginxSnippet, haproxySnippet} {
		out, err := gen(*node, 443)
		if err != nil {
			color.Red("[x] %v", err)
			return
		}
		fmt.Println()
		fmt.Println(out)
	}
}
