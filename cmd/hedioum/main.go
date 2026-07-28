package main

import (
	"flag"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/firewall"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
)

// AppVersion defines the current build version for the self-updater
// CRITICAL: This must match the GitHub Release Tag exactly (e.g., v0.4.0)
//
// v0.4.0 is a BREAKING wire-protocol change: XOR+cleartext-token was replaced by
// an authenticated ChaCha20-Poly1305 stream. A v0.4.0 node cannot talk to an
// older node — both the Iran Hub and the Foreign Egress must be updated together.
const AppVersion = "v0.4.0"

func main() {
	resetCfg := flag.Bool("reset", false, "Wipe the current configuration database and restart the setup wizard")
	openFW := flag.Bool("open-firewall", false, "Open the tunnel's listen port on the host firewall and exit (run privileged, e.g. from systemd ExecStartPre=+)")
	flag.Parse()

	if *openFW {
		handleOpenFirewall()
		return
	}

	if *resetCfg {
		handleReset()
	}

	isFirstLaunch := false
	cfg, err := config.LoadConfig()
	if err != nil {
		isFirstLaunch = true
		// No config means first launch. Force terminal wizard regardless of environment.
		printHeader()
		color.Yellow("[!] Initializing Setup Wizard for fresh installation...\n")
		cfg = runSetupWizard()
	}

	// Detect execution context: Human (Terminal) vs Systemd (Daemon)
	fileInfo, _ := os.Stdout.Stat()
	isInteractive := (fileInfo.Mode() & os.ModeCharDevice) != 0

	if isInteractive {
		if isFirstLaunch {
			color.HiBlue("\n[*] Bootstrapping background daemon...")
			err := exec.Command("systemctl", "start", "hedioum.service").Run()
			if err != nil {
				// Soft warning for non-systemd environments (e.g., local dev testing)
				color.Yellow("[-] Note: Could not auto-start systemd service. If not using systemd, start daemon manually.")
			}
			// Give systemd a moment to bind ports before showing the dashboard
			time.Sleep(1 * time.Second)
		}
		runInteractiveDashboard(cfg)
	} else {
		// Headless Daemon Execution (Systemd)
		if cfg.Role == "foreign" {
			egress.StartForeignDaemon(cfg)
		} else if cfg.Role == "iran" {
			ingress.StartIranHub(cfg)
		} else {
			// Fail securely if role is corrupted or undefined
			os.Exit(1)
		}
	}
}

// handleOpenFirewall opens the foreign egress listen port on the host firewall.
// It is meant to run as a privileged, short-lived step before the sandboxed
// daemon starts. The Iran hub listens only on 127.0.0.1, so it needs no rule.
func handleOpenFirewall() {
	cfg, err := config.LoadConfig()
	if err != nil {
		color.Yellow("[-] open-firewall: no configuration yet (%v); nothing to do.", err)
		return
	}
	if cfg.Role != "foreign" {
		return
	}

	port := cfg.ForeignListenPort
	if port == 0 {
		port = 22
	}

	backend, err := firewall.EnsurePortOpen(port)
	switch {
	case err != nil:
		color.Yellow("[-] Firewall (%s): could not open tcp/%d automatically: %v", backend, port, err)
		color.Yellow("    Please allow tcp/%d manually if remote clients cannot connect.", port)
	case backend == "none":
		color.Cyan("[i] No active host firewall detected; tcp/%d needs no rule.", port)
	default:
		color.Green("[✓] Ensured tcp/%d is open via %s.", port, backend)
	}
}

func printHeader() {
	color.Cyan("=========================================================")
	color.HiCyan("   Hedioum Dynamic Pool Tunnel - Management Dashboard")
	color.HiWhite("   Version: %s | Core: Chaos Mesh Routing", AppVersion)
	color.Cyan("=========================================================\n")
}
