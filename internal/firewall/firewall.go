// Package firewall best-effort opens a TCP listen port on whichever firewall the
// host is running, so users are not silently blocked when the tunnel binds a
// non-default port. It is distribution-agnostic (ufw, firewalld, iptables, and
// the iptables-nft shim that fronts nftables on most modern systems) and every
// operation is idempotent, so it is safe to run on every daemon start.
//
// It is intended to be invoked from a fully-privileged context (e.g. a systemd
// ExecStartPre=+ step), NOT from inside the hardened daemon sandbox, because
// editing the firewall requires CAP_NET_ADMIN and filesystem write access that
// the sandboxed daemon deliberately drops.
package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// EnsurePortOpen opens tcp/<port> on the active firewall. It returns the backend
// that handled it ("ufw", "firewalld", "iptables", or "none" when no restrictive
// firewall was detected) and an error only if a detected backend failed.
func EnsurePortOpen(port int) (string, error) {
	switch {
	case ufwActive():
		return "ufw", runQuiet("ufw", "allow", fmt.Sprintf("%d/tcp", port))

	case firewalldActive():
		// Persist across reloads and apply to the running set.
		_ = runQuiet("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%d/tcp", port))
		errRuntime := runQuiet("firewall-cmd", fmt.Sprintf("--add-port=%d/tcp", port))
		_ = runQuiet("firewall-cmd", "--reload")
		return "firewalld", errRuntime

	case iptablesRestrictive():
		// Covers legacy iptables and the iptables-nft shim (so most nftables
		// setups are handled here too). The daemon re-runs this on every start,
		// which also re-adds the rule after a reboot without needing persistence.
		return "iptables", ensureIptablesAccept(port)

	default:
		return "none", nil
	}
}

func ufwActive() bool {
	if !hasCmd("ufw") {
		return false
	}
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

func firewalldActive() bool {
	if !hasCmd("firewall-cmd") {
		return false
	}
	// `--state` exits 0 and prints "running" only when firewalld is up.
	out, err := exec.Command("firewall-cmd", "--state").CombinedOutput()
	return err == nil && strings.Contains(string(out), "running")
}

// iptablesRestrictive reports whether iptables is present and its INPUT chain
// would drop unsolicited traffic (default policy DROP/REJECT), i.e. a new port
// actually needs an explicit ACCEPT rule.
func iptablesRestrictive() bool {
	if !hasCmd("iptables") {
		return false
	}
	out, err := exec.Command("iptables", "-S", "INPUT").CombinedOutput()
	if err != nil {
		return false
	}
	return parseInputRestrictive(string(out))
}

// parseInputRestrictive inspects `iptables -S INPUT` output for a restrictive
// default policy. Kept separate for unit testing.
func parseInputRestrictive(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "-P INPUT DROP" || line == "-P INPUT REJECT" {
			return true
		}
	}
	return false
}

// ensureIptablesAccept adds an ACCEPT rule for tcp/<port> to INPUT unless one is
// already present (checked with -C for idempotency).
func ensureIptablesAccept(port int) error {
	rule := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if exec.Command("iptables", append([]string{"-C"}, rule...)...).Run() == nil {
		return nil // already allowed
	}
	return runQuiet("iptables", append([]string{"-I"}, rule...)...)
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runQuiet(name string, args ...string) error {
	if err := exec.Command(name, args...).Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
