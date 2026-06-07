package main

import (
	"fmt"
	"os"
	"os/exec"

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
		options := []string{
			"1. Show Live Service Status & Configuration",
			"2. View Real-time Logs (Journalctl)",
		}

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
			"5. Update Hedioum Daemon (Self-Update)",
			"6. Uninstall & Remove Everything",
			"0. Start Daemon Foreground (Debug)",
			"Exit",
		)

		prompt := &survey.Select{
			Message:  "Select an operational task:",
			Options:  options,
			PageSize: 12,
		}
		survey.AskOne(prompt, &action)

		switch action {
		case "1. Show Live Service Status & Configuration":
			runSystemCmd("systemctl", "status", "hedioum.service", "--no-pager")

			if cfg.Role == "iran" && len(cfg.ForeignNodes) > 0 {
				color.HiCyan("\n--- Active Egress Pools Configuration ---")
				for _, n := range cfg.ForeignNodes {
					fmt.Printf(" Alias: %s | Target: %s:%d | SOCKS: %d\n", color.HiWhiteString(n.Alias), n.TargetIP, n.TargetPort, n.LocalSocksPort)
					fmt.Printf(" Dynamics: Limit %dMbps (±%dMbps Jitter) | Max Conns: %d\n\n", n.BandwidthLimitMbps, n.BandwidthJitterMbps, n.MaxConnections)
				}
				color.Yellow("Note: Run 'journalctl -u hedioum.service -f' for live Scale-Up/Down and Mbps monitoring.")
			}

		case "2. View Real-time Logs (Journalctl)":
			color.Cyan("\n[*] Tailing logs. Press Ctrl+C to return to dashboard.\n")
			runSystemCmd("journalctl", "-u", "hedioum.service", "-f", "-n", "50")

		case "3. Add New Foreign Egress Node":
			setupIranNode(cfg, false)
			saveAndRestart(cfg)

		case "4. Remove Existing Egress Node":
			if len(cfg.ForeignNodes) == 0 {
				color.Yellow("No egress nodes registered.")
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

		case "3. Rotate Authentication Token":
			cfg.AuthToken = sysutil.GenerateSecureToken()
			color.Green("\n[✓] Token Rotated. New Token: %s", color.HiYellowString(cfg.AuthToken))
			color.Red("WARNING: You must update this token on your Iran Hub immediately.")
			saveAndRestart(cfg)

		case "5. Update Hedioum Daemon (Self-Update)":
			color.HiBlue("\n--- Core System Updater ---")
			sysutil.SelfUpdate(AppVersion)

		case "6. Uninstall & Remove Everything":
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

		case "0. Start Daemon Foreground (Debug)":
			color.Magenta("\n[*] Bootstrapping Daemon in foreground. Ctrl+C to abort.")
			if cfg.Role == "foreign" {
				egress.StartForeignDaemon(cfg)
			} else {
				ingress.StartIranHub(cfg)
			}

		case "Exit":
			fmt.Println("Exiting dashboard...")
			os.Exit(0)
		}
		fmt.Println("\n---------------------------------------------------------")
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
