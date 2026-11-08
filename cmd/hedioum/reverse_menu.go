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
	var picked string
	if err := survey.AskOne(&survey.Select{Message: "Which node to switch?", Options: labels}, &picked); err != nil {
		return
	}
	alias := byLabel[picked]
	node := findNode(cfg, alias)
	if node == nil {
		return
	}

	if node.Reverse {
		ok := true
		_ = survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Switch %q back to the normal mode (the hub dials the foreign)?", alias),
			Default: true,
		}, &ok)
		if !ok {
			return
		}
		if err := applyForwardIran(cfg, alias); err != nil {
			color.Red("[x] %v", err)
			return
		}
		commitReverse(cfg)
		color.Yellow("    Also switch the foreign back: hedioum-tunnel reverse-foreign --forward")
		return
	}

	color.HiCyan("\nReverse mode: %q will keep its token and settings, but the foreign dials this hub.", alias)
	var overrides map[string]int
	for {
		plan, err := planReverse(cfg, node, overrides)
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

	plan, tok, err := applyReverseIran(cfg, alias, overrides, "")
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	printReversePlan(alias, plan)
	commitReverse(cfg)
	color.HiGreen("\n━━━ Run this on the foreign server now ━━━")
	fmt.Printf("hedioum-tunnel reverse-foreign --token %s\n", tok)
	color.Yellow("(or choose \"Reverse Mode\" in the foreign's menu and paste the token)")
}

// runReverseForeignMenu switches the foreign to dial the hub, or back.
func runReverseForeignMenu(cfg *config.AppConfig) {
	inReverse := len(cfg.ReverseTargets) > 0
	if inReverse {
		color.HiCyan("\nThis foreign is in REVERSE mode (it dials the hub, %d endpoint(s)).", len(cfg.ReverseTargets))
		var choice string
		_ = survey.AskOne(&survey.Select{
			Message: "What now?",
			Options: []string{"Switch back to the normal mode", "Paste a new reverse token", "Cancel"},
		}, &choice)
		switch {
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
