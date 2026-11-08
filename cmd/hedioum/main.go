package main

import (
	"flag"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/egress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/firewall"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/logging"
	"golang.org/x/term"
)

// AppVersion defines the current build version for the self-updater.
// CRITICAL: This must match the GitHub Release Tag exactly (e.g., v0.6.0)
//
// v0.11.1 is a security patch: Go 1.26.10 (18 reachable stdlib vulns in
// net/http, crypto/tls, crypto/x509 on the mimic/panel/ACME paths) plus
// klauspost/compress, x/crypto, x/net, x/text bumps. Also fixes the dashboard
// "Add Node" hang (#37): the SOCKS port search no longer loops forever on an
// out-of-range port, and SOCKS/mimic ports are range-checked on every input path.
//
// v0.11.0 adds transparent L3 Gateway mode (--gateway): a hub — especially a
// single container on MikroTik/RouterOS or any Linux router — forwards transit
// traffic that arrives on its LAN-facing interface into the tunnel, so a whole LAN
// egresses through the disguised tunnel with no per-device change and no external
// proxy. Built on the 0.10 TUN engine (gVisor); routing via netlink (iif rule +
// ip_forward), with a RouterOS-7.22 ip-rule-priority guard. Validated end-to-end on
// a real RouterOS CHR and on a plain Linux router. Wire protocol UNCHANGED since
// v0.8.0; gateway/TUN are hub-side only, so v0.11 hubs interoperate with v0.9 foreigns.
const AppVersion = "v0.11.1"

func main() {
	// Management subcommands (a non-flag first argument): install, setup-*, etc.
	// The no-argument invocation (dashboard on a TTY / daemon under systemd) and
	// the --reset/--open-firewall flags fall through to the logic below.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		runSubcommand(os.Args[1], os.Args[2:])
		return
	}

	resetCfg := flag.Bool("reset", false, "Wipe the current configuration database and restart the setup wizard")
	openFW := flag.Bool("open-firewall", false, "Open the tunnel's listen port on the host firewall and exit (run privileged, e.g. from systemd ExecStartPre=+)")
	foreground := flag.Bool("foreground", false, "Run the daemon in the foreground with logs on stdout (used by the dashboard's Debug mode)")
	flag.Parse()

	if *openFW {
		handleOpenFirewall()
		return
	}

	// Foreground daemon: run the role's daemon with logs on stdout and block. The
	// dashboard's Debug option launches this as a subprocess so Ctrl+C stops just
	// the daemon and returns to the menu (see runInterruptible).
	if *foreground {
		cfg, err := config.LoadConfig()
		if err != nil {
			fail("no configuration to run: %v", err)
		}
		runDaemon(cfg)
		return
	}

	if *resetCfg {
		handleReset()
	}

	isFirstLaunch := false
	cfg, err := config.LoadConfig()
	if err != nil {
		isFirstLaunch = true
		// The setup wizard needs an interactive terminal. When stdin is not a TTY
		// (the installer's trailing `exec hedioum-tunnel` over a pipe/EOF, or a
		// systemd start with no config), running the wizard would EOF every prompt,
		// persist a bogus config, and then block. Print the non-interactive setup
		// hint and exit cleanly — the binary is installed; the operator runs setup-*.
		if !isTerminal(os.Stdin) {
			printHeader()
			color.Yellow("[!] No configuration found and no interactive terminal detected.")
			printSetupHint()
			return
		}
		printHeader()
		color.Yellow("[!] Initializing Setup Wizard for fresh installation...\n")
		cfg = runSetupWizard()
	}

	// Detect execution context: Human (Terminal) vs Systemd (Daemon)
	isInteractive := isTerminal(os.Stdout)

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
		// Headless daemon (systemd): structured logs to journald.
		runDaemon(cfg)
	}
}

// runDaemon starts the role's networking daemon and blocks. Shared by the headless
// systemd path and the --foreground debug mode.
func runDaemon(cfg *config.AppConfig) {
	logging.Init(false) // level via HEDIOUM_LOG_LEVEL (debug|info|warn|error)
	slog.Info("hedioum daemon starting", "version", AppVersion, "role", cfg.Role)
	switch cfg.Role {
	case "foreign":
		egress.StartForeignDaemon(cfg)
	case "iran":
		ingress.StartIranHub(cfg)
	default:
		// Fail securely if role is corrupted or undefined.
		slog.Error("undefined role in config; refusing to start", "role", cfg.Role)
		os.Exit(1)
	}
}

// handleOpenFirewall opens the foreign egress listen port on the host firewall.
// It is meant to run as a privileged, short-lived step before the sandboxed
// daemon starts. A forward-mode Iran hub listens only on 127.0.0.1, so it needs no
// rule; a reverse node's listener ports are opened too.
func handleOpenFirewall() {
	cfg, err := config.LoadConfig()
	if err != nil {
		color.Yellow("[-] open-firewall: no configuration yet (%v); nothing to do.", err)
		return
	}
	var ports []int
	switch cfg.Role {
	case "foreign":
		if cfg.ReverseOnly {
			return // dial-out only: this host listens on nothing
		}
		ports = firewallPorts(cfg)
	case "iran":
		// The hub listens only on loopback for SOCKS, but a reverse node also accepts
		// the pipes its foreign dials in, on public ports.
		ports = reverseFirewallPorts(cfg)
	}

	for _, port := range ports {
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
}

// firewallPorts returns every port the foreign egress must open: one per
// camouflage listener. parseConfig always populates Mimics for a foreign node
// (synthesizing a single SSH listener for legacy configs), so every active mimic
// gets a rule — not just the legacy SSH port. Falls back to the legacy port only
// if Mimics is somehow empty.
func firewallPorts(cfg *config.AppConfig) []int {
	loopback := isLoopbackBind(cfg.ListenBind)
	ports := make([]int, 0, len(cfg.Mimics))
	for _, ml := range cfg.Mimics {
		// Behind a front proxy the other listeners are only reachable through it, so
		// nothing is opened for them; the SSH mimic is never bound to the proxy address.
		if loopback && ml.Type != "ssh" {
			continue
		}
		if ml.Port != 0 {
			ports = append(ports, ml.Port)
		}
	}
	if loopback {
		return ports // the HTTP decoy is not opened either
	}
	if len(ports) == 0 {
		port := cfg.ForeignListenPort
		if port == 0 {
			port = 22
		}
		ports = append(ports, port)
	}
	// The plaintext HTTP (Apache) decoy port, when enabled.
	if cfg.HTTPDecoyPort > 0 {
		ports = append(ports, cfg.HTTPDecoyPort)
	}
	return ports
}

// isTerminal reports whether f is attached to an interactive TTY rather than a
// pipe, regular file, or /dev/null. It uses an ioctl (TCGETS) probe: a plain
// ModeCharDevice check is not enough because /dev/null is itself a character
// device, so under Docker (whose default stdin is /dev/null) it would falsely
// look interactive and launch the wizard into an EOF loop.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// printSetupHint prints the non-interactive configuration commands, shown when the
// binary is launched with no config on a non-interactive stdin.
func printSetupHint() {
	color.HiWhite("\nConfigure non-interactively, then start the service:")
	color.HiWhite("  Foreign: hedioum-tunnel setup-foreign            (auto-picks a persona; prints a pairing token)")
	color.HiWhite("  Iran:    hedioum-tunnel setup-iran --alias NAME --token <PAIRING_TOKEN> --socks-port N")
	color.HiWhite("  Then:    systemctl start hedioum.service")
	color.HiBlack("  (The pairing token carries the IP, ports and persona — no --target-ip/--mimics needed.)")
	color.HiBlack("  (Or run 'hedioum-tunnel' on an interactive terminal for the guided wizard.)")
}

func printHeader() {
	color.Cyan("=========================================================")
	color.HiCyan("   Hedioum Dynamic Pool Tunnel - Management Dashboard")
	color.HiWhite("   Version: %s | Core: Chaos Mesh Routing", AppVersion)
	color.Cyan("=========================================================\n")
}
