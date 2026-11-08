package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/tunproto"
)

// --- INTERACTIVE OPERATIONS DASHBOARD ---

func runInteractiveDashboard(cfg *config.AppConfig) {
	printHeader()

	for {
		var action string
		var options []string

		// Build dynamic, sequentially numbered menu options based on role
		options = append(options,
			"1. Show Live Service Status & Monitoring",
			"2. View Real-time Logs (Journalctl)",
		)

		if cfg.Role == "iran" {
			options = append(options,
				"3. Add New Foreign Egress Node",
				"4. Edit Existing Egress Node",
				"5. Remove Existing Egress Node",
				"6. Run Speedtest to a Node",
				"7. Probe Endpoints (per-mimic reachability)",
				"8. Test Connection (full egress: exit IP, sites, DNS, TUN)",
				"9. Check This Server's IP Reputation",
				"10. Restart the Service (reset all pools)",
				"11. Reverse Tunnel: Switch a Node Normal <-> Reverse",
			)
		} else {
			options = append(options,
				"3. Edit Foreign Configuration",
				"4. Rotate Authentication Token",
				"5. Check Egress IP Reputation",
				"6. Restart the Service",
				"7. Reverse Mode: Dial the Hub (when the hub can't reach this server)",
			)
		}

		// Enterprise Features added to the bottom of the menu
		options = append(options,
			"----------------------------------------",
			"U. Update Hedioum Daemon (Self-Update)",
			"X. Uninstall & Remove Everything",
			"D. Start Daemon Foreground (Debug)",
			"0. Exit",
		)

		prompt := &survey.Select{
			Message:  "Select an operational task:",
			Options:  options,
			PageSize: 12,
		}
		survey.AskOne(prompt, &action)

		// Extract the core action bypassing the dynamic prefixes
		switch {
		case strings.Contains(action, "Show Live Service Status"):
			// Print clean systemd status summary
			color.HiCyan("\n=== [ System Daemon Status ] ===")
			runSystemCmd("systemctl", "status", "hedioum.service", "--no-pager", "-n", "0")

			if cfg.Role == "iran" {
				if len(cfg.ForeignNodes) > 0 {
					color.HiCyan("\n=== [ Active Mesh Topologies & Live Stats ] ===")
					for _, n := range cfg.ForeignNodes {
						fmt.Printf("\n 🟢 Target Alias : %s\n", color.HiWhiteString(n.Alias))
						if n.Reverse {
							fmt.Printf(" ├─ Mode         : %s (the foreign dials this hub)\n", color.HiYellowString("REVERSE"))
						}
						fmt.Printf(" ├─ Local SOCKS5 : 127.0.0.1:%d\n", n.LocalSocksPort)
						if n.TunEnabled || n.GatewayEnabled {
							dnsNote := ""
							if n.DNSEnabled {
								dnsNote = fmt.Sprintf(" + DNS %s:53", tunGatewayIP(n.TunAddr))
							}
							fmt.Printf(" ├─ TUN Egress   : %s @ %s%s\n", color.HiGreenString(n.TunName), n.TunAddr, dnsNote)
						}
						if n.GatewayEnabled {
							scope := "all transit"
							if len(n.GatewayLAN) > 0 {
								scope = strings.Join(n.GatewayLAN, ",")
							}
							iface := n.GatewayIface
							if iface == "" {
								iface = "auto"
							}
							fmt.Printf(" ├─ Gateway      : %s (forward %s from %s)\n", color.HiGreenString("on"), scope, iface)
						}
						fmt.Printf(" ├─ Pool Sizing  : %d (Warm-up) to %d (Max Peak) Connections\n", n.MinConnections, n.MaxConnections)
						fmt.Printf(" ├─ DPI Evasion  : Floating Cap %d Mbps (±%d Mbps Jitter)\n", n.BandwidthLimitMbps, n.BandwidthJitterMbps)
						fmt.Printf(" └─ Endpoints    : %d mimic(s)\n", len(n.Endpoints))
						for i, ep := range n.Endpoints {
							branch := "    ├─"
							if i == len(n.Endpoints)-1 {
								branch = "    └─"
							}
							fmt.Printf("%s %-6s → %s\n", branch, color.HiCyanString(ep.Mimic), color.HiYellowString(ep.Target))
						}
					}
					color.Yellow("\n[*] Note: To view real-time Mbps and connection scale events, use Option 2 (Journalctl).")
					color.Yellow("    (Live RPC Dashboard memory-link is slated for the next release).")
				} else {
					color.Yellow("\n[!] No active egress nodes configured. Use Option 3 to add one.")
				}
			} else if cfg.Role == "foreign" {
				// Display critical connection info for the foreign server
				color.HiCyan("\n=== [ Egress Node Details ] ===")
				personaLabel := cfg.Persona
				if personaLabel == "" {
					personaLabel = "custom"
				}
				fmt.Printf(" ├─ Persona     : %s (%d mimics)\n", personaLabel, len(cfg.Mimics))
				if len(cfg.ReverseTargets) > 0 {
					fmt.Printf(" ├─ Mode        : %s (dials the hub, %d endpoint(s))\n", color.HiYellowString("REVERSE"), len(cfg.ReverseTargets))
				}
				fmt.Printf(" ├─ Listen Port : %d\n", cfg.ForeignListenPort)
				fmt.Printf(" └─ Auth Token  : %s\n", color.HiYellowString(cfg.AuthToken))
				color.HiBlack("    (Use this token when configuring your Iran Hub)")
			}

		case strings.Contains(action, "View Real-time Logs"):
			color.Cyan("\n[*] Tailing logs. Press Ctrl+C to return to the dashboard.\n")
			runInterruptible("journalctl", "-u", "hedioum.service", "-f", "-n", "30")

		case strings.Contains(action, "Add New Foreign Egress Node"):
			setupIranNode(cfg, false)
			saveAndRestart(cfg)

		case strings.Contains(action, "Edit Existing Egress Node"):
			if node, ok := pickNode(cfg, "Select node to edit:"); ok {
				editIranNode(cfg, node)
				saveAndRestart(cfg)
			}

		case strings.Contains(action, "Edit Foreign Configuration"):
			editForeignConfig(cfg)
			saveAndRestart(cfg)

		case strings.Contains(action, "Remove Existing Egress Node"):
			if len(cfg.ForeignNodes) == 0 {
				color.Yellow("\n[!] No egress nodes registered.")
				continue
			}
			var aliases []string
			for _, n := range cfg.ForeignNodes {
				aliases = append(aliases, n.Alias)
			}
			var selected string
			survey.AskOne(&survey.Select{Message: "Select node to terminate and remove:", Options: aliases}, &selected)

			if cfg.RemoveForeignNode(selected) {
				saveAndRestart(cfg)
			}

		case strings.Contains(action, "Run Speedtest"):
			runSpeedtestMenu(cfg)

		case strings.Contains(action, "Probe Endpoints"):
			runProbeMenu(cfg)

		case strings.Contains(action, "Test Connection"):
			if node, ok := pickNode(cfg, "Select node to test:"); ok {
				testNodeConnection(node)
			}

		case strings.Contains(action, "IP Reputation"):
			cmdCheckIP(nil)

		case strings.Contains(action, "Reverse Tunnel: Switch a Node"):
			runReverseIranMenu(cfg)

		case strings.Contains(action, "Reverse Mode: Dial the Hub"):
			runReverseForeignMenu(cfg)

		case strings.Contains(action, "Restart the Service"):
			color.HiBlue("\n[*] Restarting hedioum.service (re-warms every pool)...")
			if err := exec.Command("systemctl", "restart", "hedioum.service").Run(); err != nil {
				color.Yellow("[-] Restart failed (are you root?): %v", err)
			} else {
				color.Green("[✓] Service restarted; pools re-warming.")
			}

		case strings.Contains(action, "Rotate Authentication Token"):
			cfg.AuthToken = sysutil.GenerateSecureToken()
			color.Green("\n[✓] Token Rotated. New Token: %s", color.HiYellowString(cfg.AuthToken))
			color.HiRed("WARNING: You must update this token on your Iran Hub immediately.")
			saveAndRestart(cfg)

		case strings.Contains(action, "Update Hedioum Daemon"):
			color.HiBlue("\n--- Core System Updater ---")
			sysutil.SelfUpdate(AppVersion)

		case strings.Contains(action, "Uninstall & Remove Everything"):
			color.HiRed("\n--- DESTROY SYSTEM ---")
			confirm := false
			survey.AskOne(&survey.Confirm{
				Message: "Are you absolutely sure? This will delete the daemon, configs, and binaries.",
				Default: false,
			}, &confirm)

			if confirm {
				sysutil.Uninstall()
			} else {
				color.Green("[-] Uninstall aborted.")
			}

		case strings.Contains(action, "Start Daemon Foreground"):
			color.Magenta("\n[*] Running daemon in foreground (debug). Press Ctrl+C to stop and return to the menu.\n")
			if self, err := os.Executable(); err != nil {
				color.Red("[x] Cannot locate the binary: %v", err)
			} else {
				// Run as a subprocess so Ctrl+C stops just the daemon (releasing its
				// ports) and returns here, instead of killing the dashboard.
				runInterruptible(self, "--foreground")
			}

		case strings.Contains(action, "Exit"):
			fmt.Println("Exiting dashboard...")
			os.Exit(0)
		}

		// Print a clean separator before the menu loops again
		fmt.Println(strings.Repeat("-", 60))
	}
}

// pickNode prompts for a node alias (auto-selects when only one exists). Returns
// false if there are no nodes.
func pickNode(cfg *config.AppConfig, prompt string) (config.ForeignNode, bool) {
	if len(cfg.ForeignNodes) == 0 {
		color.Yellow("\n[!] No egress nodes configured. Use Option 3 to add one.")
		return config.ForeignNode{}, false
	}
	if len(cfg.ForeignNodes) == 1 {
		return cfg.ForeignNodes[0], true
	}
	var aliases []string
	for _, n := range cfg.ForeignNodes {
		aliases = append(aliases, n.Alias)
	}
	var selected string
	survey.AskOne(&survey.Select{Message: prompt, Options: aliases}, &selected)
	for _, n := range cfg.ForeignNodes {
		if n.Alias == selected {
			return n, true
		}
	}
	return config.ForeignNode{}, false
}

// runSpeedtestMenu runs an un-shaped throughput test to a chosen node from the TUI.
func runSpeedtestMenu(cfg *config.AppConfig) {
	node, ok := pickNode(cfg, "Speedtest which node?")
	if !ok {
		return
	}
	ep := node.Endpoints[0] // first endpoint; CLI `speedtest --mimic` targets a specific one
	color.HiCyan("\n[*] Speedtest to %q via %s@%s (8s/direction)...", node.Alias, ep.Mimic, ep.Target)
	down, err := runSpeedtest(ep, node.AuthToken, tunproto.SpeedDown, 8)
	report("download", down, err)
	up, err := runSpeedtest(ep, node.AuthToken, tunproto.SpeedUp, 8)
	report("upload", up, err)
}

// runProbeMenu tests every endpoint of a chosen node and reports reachability.
func runProbeMenu(cfg *config.AppConfig) {
	node, ok := pickNode(cfg, "Probe which node?")
	if !ok {
		return
	}
	fmt.Printf("\nNode %q (%d endpoints):\n", node.Alias, len(node.Endpoints))
	for _, ep := range node.Endpoints {
		rtt, err := ingress.ProbeEndpoint(ep, node.AuthToken)
		if err != nil {
			color.Red("  ✗ %-6s %-24s FAIL: %v", ep.Mimic, ep.Target, err)
		} else {
			color.Green("  ✓ %-6s %-24s OK  (%.0f ms)", ep.Mimic, ep.Target, float64(rtt.Microseconds())/1000)
		}
	}
}

// saveAndRestart commits config changes and performs a graceful systemd restart
func saveAndRestart(cfg *config.AppConfig) {
	if err := config.SaveConfig(cfg); err != nil {
		color.Red("[x] Failed to commit changes to storage: %v", err)
		return
	}
	color.Green("[✓] Configuration saved.")

	// Execute non-blocking service restart if managed by systemd
	color.HiBlue("[*] Restarting background daemon to apply state changes...")
	err := exec.Command("systemctl", "restart", "hedioum.service").Run()
	if err != nil {
		color.Yellow("[-] Systemd restart failed (Are you running as root?). Apply changes manually.")
	} else {
		color.Green("[✓] Daemon reloaded successfully.")
	}
}

// runSystemCmd acts as a bridge to execute system binaries directly within the TUI
func runSystemCmd(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

// runInterruptible runs a long-lived, terminal-attached command (a log tail, the
// foreground daemon) but treats Ctrl+C as "stop this command and return to the
// menu" rather than "quit the dashboard". While the child runs we catch SIGINT in
// this process so the parent survives; the child, whose SIGINT disposition resets
// to the default on exec, still receives Ctrl+C from the terminal and exits.
func runInterruptible(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sig: // absorb Ctrl+C here; the child handles it and exits
			case <-done:
				return
			}
		}
	}()

	_ = cmd.Run()
	close(done)
	signal.Stop(sig)
}
