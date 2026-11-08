package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/ingress"
	"golang.org/x/net/proxy"
)

// cmdTestConnection runs a comprehensive, human-readable connectivity test for one (or
// every) hub node: per-mimic reachability, then real egress through the tunnel — the
// exit IP (matched against the node's foreign), a couple of censored sites, and remote
// DNS (a hostname resolved through the tunnel, proving no local DNS leak). When a node
// has TUN mode enabled it also verifies egress through that interface.
func cmdTestConnection(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	nodeAlias := fs.String("node", "", "node alias to test (default: all nodes)")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil {
		fail("could not load config: %v", err)
	}
	if cfg.Role != "iran" {
		fail("connection test runs on the Iran hub (this node's role is %q)", cfg.Role)
	}
	if len(cfg.ForeignNodes) == 0 {
		fail("no foreign nodes configured; add one first")
	}

	tested := 0
	for _, n := range cfg.ForeignNodes {
		if *nodeAlias != "" && n.Alias != *nodeAlias {
			continue
		}
		testNodeConnection(n)
		tested++
	}
	if tested == 0 {
		fail("no node matched %q", *nodeAlias)
	}
}

func testNodeConnection(n config.ForeignNode) {
	color.HiCyan("\n=== Connection test: %s ===", n.Alias)
	foreignIP := nodeTargetIP(n)

	// 1. Per-mimic reachability (the tunnel handshake end-to-end).
	color.HiWhite(" Endpoints (probe):")
	reachable := 0
	endpoints := n.Endpoints
	if n.Reverse {
		// The foreign dials in: there is no endpoint for the hub to probe. The SOCKS
		// egress test below still proves the reverse pipes work end to end.
		color.HiBlack("   (reverse mode: the foreign dials in; skipping per-endpoint probes)")
		endpoints = nil
	}
	for _, ep := range endpoints {
		rtt, err := ingress.ProbeEndpoint(ep, n.AuthToken)
		if err != nil {
			color.Red("   ✗ %-11s %-24s FAILED (%v)", ep.Mimic, ep.Target, compactErr(err))
			continue
		}
		color.Green("   ✓ %-11s %-24s OK (%d ms)", ep.Mimic, ep.Target, rtt.Milliseconds())
		reachable++
	}
	if reachable == 0 && !n.Reverse {
		color.Red(" [x] No endpoint is reachable — the tunnel cannot come up. Check the foreign and firewall.")
		return
	}
	color.HiBlack("   %d/%d endpoints reachable.", reachable, len(n.Endpoints))

	// 2. SOCKS egress (always on). Reach the listener on loopback unless it is bound
	// to a specific non-loopback address (e.g. a container veth IP), in which case
	// dial that address directly.
	socksHost := "127.0.0.1"
	if n.SocksBind != "" && n.SocksBind != "0.0.0.0" && n.SocksBind != "::" && n.SocksBind != "127.0.0.1" && n.SocksBind != "localhost" {
		socksHost = n.SocksBind
	}
	socksAddr := net.JoinHostPort(socksHost, fmt.Sprintf("%d", n.LocalSocksPort))
	color.HiWhite(" SOCKS egress (%s):", socksAddr)
	runEgressChecks(socksHTTPClient(socksAddr), foreignIP)

	// 3. TUN egress (only if enabled for this node).
	if n.TunEnabled {
		gw := tunGatewayIP(n.TunAddr)
		color.HiWhite(" TUN egress (%s via %s):", n.TunName, gw)
		if _, err := net.InterfaceByName(n.TunName); err != nil {
			color.Red("   ✗ interface %s is not up: %v", n.TunName, err)
		} else {
			// Bind test traffic to the gateway source IP and, via an isolated policy
			// route, steer just that source into the TUN — so the check exercises the
			// real datapath (source IP → TUN → SOCKS → foreign) without ever touching
			// the host's main table or default route (SSH stays safe).
			cleanup, routed := ensureTunTestRoute(gw, n.TunName)
			defer cleanup()
			if !routed {
				color.Yellow("   ! no temporary test route installed (need root + iproute2); result may reflect the host route, not the TUN.")
			}
			runEgressChecks(tunHTTPClient(gw), foreignIP)
			if n.DNSEnabled {
				checkDNSForwarder(gw)
			}
		}
	} else {
		color.HiBlack(" TUN egress: not enabled for this node (SOCKS only).")
	}
}

// ensureTunTestRoute installs a temporary, isolated source-based route so that
// packets originating from the TUN gateway IP are sent into the TUN interface,
// then returns a cleanup func. It uses a dedicated routing table + rule priority
// and never modifies the main table, so the host default route (and SSH) are
// untouched. Best-effort: returns ok=false if iproute2/root is unavailable.
func ensureTunTestRoute(gatewayIP, tunName string) (cleanup func(), ok bool) {
	noop := func() {}
	if _, err := exec.LookPath("ip"); err != nil {
		return noop, false
	}
	const table = "5199"
	const prio = "5199"
	// Clear any stale leftovers from an interrupted run.
	_ = exec.Command("ip", "rule", "del", "priority", prio).Run()
	_ = exec.Command("ip", "route", "flush", "table", table).Run()

	if err := exec.Command("ip", "route", "add", "default", "dev", tunName, "table", table).Run(); err != nil {
		return noop, false
	}
	if err := exec.Command("ip", "rule", "add", "from", gatewayIP, "lookup", table, "priority", prio).Run(); err != nil {
		_ = exec.Command("ip", "route", "flush", "table", table).Run()
		return noop, false
	}
	return func() {
		_ = exec.Command("ip", "rule", "del", "from", gatewayIP, "lookup", table, "priority", prio).Run()
		_ = exec.Command("ip", "route", "flush", "table", table).Run()
	}, true
}

// runEgressChecks verifies real egress through a client bound to the tunnel: the exit
// IP (matched to the foreign), a censored site, and remote DNS via a hostname dial.
func runEgressChecks(client *http.Client, foreignIP string) {
	exit, err := httpGetString(client, "https://api.ipify.org")
	switch {
	case err != nil:
		color.Red("   ✗ exit IP: request failed (%v)", compactErr(err))
	case foreignIP != "" && strings.TrimSpace(exit) == foreignIP:
		color.Green("   ✓ exit IP: %s (matches the foreign)", exit)
	default:
		color.Yellow("   ! exit IP: %s (foreign is %s)", strings.TrimSpace(exit), foreignIP)
	}
	// Censored-site reachability (also exercises remote DNS: the hostname is resolved
	// through the tunnel, so a 200 proves there is no local DNS leak).
	for _, u := range []string{"https://www.youtube.com", "https://www.instagram.com"} {
		code, err := httpStatus(client, u)
		if err != nil {
			color.Red("   ✗ %s → %v", u, compactErr(err))
			continue
		}
		if code >= 200 && code < 400 {
			color.Green("   ✓ %s → %d", u, code)
		} else {
			color.Yellow("   ! %s → %d", u, code)
		}
	}
}

// checkDNSForwarder resolves a name against the node's own :53 forwarder.
func checkDNSForwarder(gw string) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(gw, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if ips, err := r.LookupHost(ctx, "www.google.com"); err == nil && len(ips) > 0 {
		color.Green("   ✓ DNS forwarder %s:53 resolved www.google.com → %s", gw, ips[0])
	} else {
		color.Red("   ✗ DNS forwarder %s:53 did not resolve (%v)", gw, err)
	}
}

// socksHTTPClient builds an HTTP client that egresses through the node's SOCKS5 port,
// resolving hostnames remotely (at the foreign) so DNS never leaks locally.
func socksHTTPClient(socksAddr string) *http.Client {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return &http.Client{Timeout: time.Second} // will fail fast in the checks
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		},
	}}
}

// tunHTTPClient builds an HTTP client whose sockets are bound to the TUN gateway IP,
// so its traffic is routed into that node's tunnel.
func tunHTTPClient(gatewayIP string) *http.Client {
	local := &net.TCPAddr{IP: net.ParseIP(gatewayIP)}
	dialer := &net.Dialer{Timeout: 15 * time.Second, LocalAddr: local}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dialer.DialContext}}
}

func httpGetString(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	return string(b), err
}

func httpStatus(c *http.Client, url string) (int, error) {
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func compactErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 40 {
		return s[i+2:]
	}
	if len(s) > 60 {
		return s[:60]
	}
	return s
}
