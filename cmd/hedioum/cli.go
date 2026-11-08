package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// runSubcommand dispatches a non-flag first argument to a management command.
// The no-argument invocation (dashboard on a TTY / daemon under systemd) is
// handled by main() and never reaches here.
func runSubcommand(name string, args []string) {
	switch name {
	case "version":
		printVersion()
	case "setup-foreign":
		cmdSetupForeign(args)
	case "setup-iran":
		cmdSetupIran(args)
	case "add-node":
		cmdAddNode(args)
	case "edit-node":
		cmdEditNode(args)
	case "remove-node":
		cmdRemoveNode(args)
	case "edit-foreign":
		cmdEditForeign(args)
	case "reverse-iran":
		cmdReverseIran(args)
	case "add-hub":
		cmdAddHub(args)
	case "edit-hub":
		cmdEditHub(args)
	case "remove-hub":
		cmdRemoveHub(args)
	case "list-hubs":
		cmdListHubs(args)
	case "reverse-shared-auth":
		cmdReverseSharedAuth(args)
	case "front-proxy":
		cmdFrontProxy(args)
	case "pairing-token":
		cmdPairingToken(args)
	case "reverse-foreign":
		cmdReverseForeign(args)
	case "install":
		cmdInstall(args)
	case "uninstall":
		cmdUninstall(args)
	case "update":
		cmdUpdate(args)
	case "speedtest":
		cmdSpeedtest(args)
	case "probe":
		cmdProbe(args)
	case "test":
		cmdTestConnection(args)
	case "check-ip":
		cmdCheckIP(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		color.Red("[x] Unknown command %q", name)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Print(`Hedioum Dynamic Pool Tunnel

Usage:
  hedioum-tunnel                      Interactive dashboard (TTY) or daemon (systemd)
  hedioum-tunnel version              Print version and build info
  hedioum-tunnel install              Install/enable the systemd service (self-copy)
  hedioum-tunnel uninstall [--yes]    Stop, disable, and remove everything
  hedioum-tunnel update [--file PATH]  Update from GitHub, or from a local binary

  hedioum-tunnel setup-foreign [flags]   Write the foreign (egress) config
      --listen-port N (default 22)  --decoy-port N (default 2022)
      --egress-mode ipv4|ipv6|dual  --egress-bind-ip IP  --move-ssh  --token HEX

  hedioum-tunnel edit-foreign [flags]    Edit the foreign config in place (only the
      flags you pass change; token kept unless --token/--rotate-token)
  hedioum-tunnel setup-iran   [flags]    Write the Iran (hub) config with one node
  hedioum-tunnel add-node     [flags]    Append a foreign node to the hub config
      --alias NAME  --target HOST:PORT  --socks-port N  --token HEX
      [--min N --max N --bw N --jitter N]
      [--tun [--tun-name hedioumN] [--tun-addr 10.200.N.1/24] [--dns]]
          --tun also exposes the node as an OS-level interface (opt-in; SOCKS stays
          on). --tun-name/--tun-addr auto-assign when omitted; --dns adds a leak-free
          :53 forwarder on the gateway IP.
  hedioum-tunnel edit-node --alias NAME [flags]  Edit a node in place (only the flags
      you pass change; token kept unless --token/--rotate-token)
  hedioum-tunnel remove-node --alias NAME
  hedioum-tunnel reverse-iran --alias NAME [--ports tls=443,...] [--public-ip IP] [--forward]
      Flip an existing node to REVERSE mode (the foreign dials the hub instead of the hub
      dialing the foreign) and print a reverse pairing token; --forward flips it back
      Behind nginx/HAProxy on a shared port: --sni NAME --advertise-ports TYPE=443
      --bind 127.0.0.1 [--proxy-protocol]  (settings are remembered per node)
  hedioum-tunnel add-hub --token T [--name N] [--min 12] [--max 24] (foreign, reverse mode)
      Dial one more Iran hub with its own pipe range: at least --min pipes always, up to
      --max under load. Also: edit-hub --name N [--min --max], remove-hub --name N, list-hubs.
      Bandwidth/jitter stay on each hub's node (edit-node there).
  hedioum-tunnel reverse-shared-auth [--on|--off]
      Advanced (hub, default off): let several reverse nodes share ONE listener / SNI; the
      hub tells them apart by token. Join a node with reverse-iran --alias NEW --share-with OLD
  hedioum-tunnel front-proxy [--alias NAME] [--kind nginx|haproxy] [--public-port 443]
      Print the nginx/HAProxy config that routes the tunnel's SNI to its listener
      (on the hub: --alias of a reverse node; on a foreign: its own listener)
  hedioum-tunnel pairing-token [--public-ip IP]
      (foreign) Print the paste-only pairing token for the hub, honoring --advertise-ports
  hedioum-tunnel reverse-foreign --token REVERSE_TOKEN [--conns N] [--keep-listeners] [--forward]
      Make this foreign dial out to the hub (paste the token from reverse-iran);
      --forward restores the normal inbound mode
  hedioum-tunnel speedtest [--node NAME] [--mimic ssh|tls] [--seconds N] [--dir down|up|both]
  hedioum-tunnel probe     [--node NAME]    Test each endpoint (mimic) and report reachability
  hedioum-tunnel check-ip                   Report the egress IP's reputation (clean vs flagged)

Flags for the default mode:
  --reset            Wipe the config and re-run the setup wizard
  --open-firewall    Open the listen port on the host firewall and exit
`)
}

// --- validation helpers (shared with the wizard) ---

func validPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range (1..65535)", p)
	}
	return nil
}

func validIP(s string) error {
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address %q", s)
	}
	return nil
}

// validTarget checks a HOST:PORT where HOST is an IPv4/IPv6 literal or hostname.
func validTarget(s string) error {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("target must be HOST:PORT: %w", err)
	}
	if host == "" {
		return fmt.Errorf("target host is empty")
	}
	if net.ParseIP(host) == nil && strings.ContainsAny(host, " \t/\\") {
		return fmt.Errorf("invalid target host %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid target port %q", portStr)
	}
	return validPort(port)
}

// validToken requires a non-trivial hex string (the tokens we generate are 32 hex).
func validToken(s string) error {
	if len(s) < 8 {
		return fmt.Errorf("token too short (need >= 8 chars)")
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("token must be hexadecimal")
		}
	}
	return nil
}

// fail prints an error and exits non-zero (for CLI command handlers).
func fail(format string, a ...interface{}) {
	color.Red("[x] "+format, a...)
	os.Exit(1)
}
