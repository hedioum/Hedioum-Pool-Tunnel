package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
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
				"4. Remove Existing Egress Node",
			)
		} else {
			options = append(options, "3. Rotate Authentication Token")
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
						fmt.Printf(" ├─ Egress IP    : %s:%d\n", color.HiYellowString(n.TargetIP), n.TargetPort)
						fmt.Printf(" ├─ Local SOCKS5 : 127.0.0.1:%d\n", n.LocalSocksPort)
						fmt.Printf(" ├─ Pool Sizing  : %d (Warm-up) to %d (Max Peak) Connections\n", n.MinConnections, n.MaxConnections)
						fmt.Printf(" └─ DPI Evasion  : Floating Cap %d Mbps (±%d Mbps Jitter)\n", n.BandwidthLimitMbps, n.BandwidthJitterMbps)
					}
					color.Yellow("\n[*] Note: To view real-time Mbps and connection scale events, use Option 2 (Journalctl).")
					color.Yellow("    (Live RPC Dashboard memory-link is slated for the next release).")
				} else {
					color.Yellow("\n[!] No active egress nodes configured. Use Option 3 to add one.")
				}
			} else if cfg.Role == "foreign" {
				// Display critical connection info for the foreign server
				color.HiCyan("\n=== [ Egress Node Details ] ===")
				fmt.Printf(" ├─ Listen Port : %d\n", cfg.ForeignListenPort)
				fmt.Printf(" └─ Auth Token  : %s\n", color.HiYellowString(cfg.AuthToken))
				color.HiBlack("    (Use this token when configuring your Iran Hub)")
			}

		case strings.Contains(action, "View Real-time Logs"):
			color.Cyan("\n[*] Tailing logs. Press Ctrl+C to return to dashboard.\n")
			runSystemCmd("journalctl", "-u", "hedioum.service", "-f", "-n", "30")

		case strings.Contains(action, "Add New Foreign Egress Node"):
			setupIranNode(cfg, false)
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
			color.Magenta("\n[*] Bootstrapping Daemon in foreground. Ctrl+C to abort.")
			if cfg.Role == "foreign" {
				egress.StartForeignDaemon(cfg)
			} else {
				ingress.StartIranHub(cfg)
			}

		case strings.Contains(action, "Exit"):
			fmt.Println("Exiting dashboard...")
			os.Exit(0)
		}

		// Print a clean separator before the menu loops again
		fmt.Println(strings.Repeat("-", 60))
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
