package main

import (
	"flag"
	"os"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
)

// AppVersion defines the current build version for the self-updater
const AppVersion = "v0.1.0"

func main() {
	resetCfg := flag.Bool("reset", false, "Wipe the current configuration database and restart the setup wizard")
	flag.Parse()

	if *resetCfg {
		handleReset()
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		// No config means first launch. Force terminal wizard regardless of environment.
		printHeader()
		color.Yellow("[!] Initializing Setup Wizard for fresh installation...\n")
		cfg = runSetupWizard()
	}

	// Detect execution context: Human (Terminal) vs Systemd (Daemon)
	fileInfo, _ := os.Stdout.Stat()
	isInteractive := (fileInfo.Mode() & os.ModeCharDevice) != 0

	if isInteractive {
		runInteractiveDashboard(cfg)
	} else {
		// Headless Daemon Execution (Systemd)
		if cfg.Role == "foreign" {
			egress.StartForeignDaemon(cfg)
		} else if cfg.Role == "iran" {
			ingress.StartIranHub(cfg)
		} else {
			os.Exit(1)
		}
	}
}

func printHeader() {
	color.Cyan("=========================================================")
	color.HiCyan("   Hedioum Dynamic Pool Tunnel - Management Dashboard")
	color.HiWhite("   Version: %s | Core: Chaos Mesh Routing", AppVersion)
	color.Cyan("=========================================================\n")
}
