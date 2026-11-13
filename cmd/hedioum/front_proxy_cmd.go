package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// front-proxy prints the nginx / HAProxy configuration that routes the tunnel's SNI to
// the foreign's listener, so the tunnel and other services (a panel, user configs...) can
// share one public port such as 443. It only prints: it never edits the proxy's files.

// frontSpec is what a front proxy needs to know about the tunnel listener it fronts.
type frontSpec struct {
	Upstream      string // host:port of the tunnel listener the proxy forwards to
	SNI           string // the SNI that identifies tunnel traffic
	ProxyProtocol bool   // whether the listener requires a PROXY protocol header
	// Sources, when set, routes by the connecting IP instead of the SNI: these addresses
	// (the hub) always go to the tunnel listener, every other client keeps going where the
	// SNI sends it. This lets the tunnel use the SAME SNI as a real service on that port,
	// which SNI routing alone cannot do.
	Sources []string
}

// nginxFor renders the nginx stream configuration for a spec.
func nginxFor(sp frontSpec, publicPort int) string {
	if len(sp.Sources) > 0 {
		return nginxBySource(sp, publicPort)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# nginx (needs the stream and ssl_preread modules)\n")
	fmt.Fprintf(&b, "# 1) If you already have a stream block listening on :%d with ssl_preread, add ONE line\n", publicPort)
	fmt.Fprintf(&b, "#    to its map and keep everything else as it is:\n\n")
	fmt.Fprintf(&b, "    %s  %s;\n\n", sp.SNI, sp.Upstream)
	if sp.ProxyProtocol {
		fmt.Fprintf(&b, "# The tunnel listener requires the PROXY protocol, so the stream server that listens on :%d must\n", publicPort)
		fmt.Fprintf(&b, "# have `proxy_protocol on;` (every upstream of that server then receives the header).\n\n")
	} else {
		fmt.Fprintf(&b, "# The tunnel listener does NOT use the PROXY protocol, so the stream server on :%d must NOT have\n", publicPort)
		fmt.Fprintf(&b, "# `proxy_protocol on;`. If it does (other upstreams need it), enable the PROXY protocol on the\n")
		fmt.Fprintf(&b, "# tunnel listener too (--proxy-protocol), which is simpler than a helper server.\n\n")
	}
	fmt.Fprintf(&b, "# 2) Or, with no stream block yet, a complete minimal one (the default upstream is where\n")
	fmt.Fprintf(&b, "#    :%d traffic went before; replace 127.0.0.1:8444 with it):\n\n", publicPort)
	fmt.Fprintf(&b, "stream {\n")
	fmt.Fprintf(&b, "    map $ssl_preread_server_name $backend {\n")
	fmt.Fprintf(&b, "        %s  %s;\n", sp.SNI, sp.Upstream)
	fmt.Fprintf(&b, "        default  127.0.0.1:8444;\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "    server {\n")
	fmt.Fprintf(&b, "        listen %d;\n", publicPort)
	fmt.Fprintf(&b, "        ssl_preread on;\n")
	fmt.Fprintf(&b, "        proxy_pass $backend;\n")
	if sp.ProxyProtocol {
		fmt.Fprintf(&b, "        proxy_protocol on;\n")
	}
	fmt.Fprintf(&b, "    }\n}\n\n")
	fmt.Fprintf(&b, "# Then: nginx -t && systemctl reload nginx\n")
	return b.String()
}

// nginxBySource renders the nginx configuration that sends the listed source IPs to the
// tunnel listener whatever SNI they present, and everyone else by SNI as before.
func nginxBySource(sp frontSpec, publicPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nginx (needs the stream and ssl_preread modules): route by SOURCE IP, so the tunnel can share\n")
	fmt.Fprintf(&b, "# an SNI with a real service. These addresses go to the tunnel; everyone else goes where the\n")
	fmt.Fprintf(&b, "# SNI sends them, exactly as before.\n\n")
	fmt.Fprintf(&b, "# 1) In your existing stream block, keep your SNI map (called $by_sni here; use your own name)\n")
	fmt.Fprintf(&b, "#    and add this map after it:\n\n")
	fmt.Fprintf(&b, "    map $remote_addr $tunnel_or_sni {\n")
	for _, ip := range sp.Sources {
		fmt.Fprintf(&b, "        %s  %s;\n", ip, sp.Upstream)
	}
	fmt.Fprintf(&b, "        default  $by_sni;\n")
	fmt.Fprintf(&b, "    }\n\n")
	fmt.Fprintf(&b, "#    then change `proxy_pass $by_sni;` of the :%d server to `proxy_pass $tunnel_or_sni;`.\n", publicPort)
	if sp.ProxyProtocol {
		fmt.Fprintf(&b, "#    The tunnel listener requires the PROXY protocol, so that server needs `proxy_protocol on;`.\n\n")
	} else {
		fmt.Fprintf(&b, "#    The tunnel listener does NOT use the PROXY protocol, so that server must NOT have\n")
		fmt.Fprintf(&b, "#    `proxy_protocol on;` (or enable --proxy-protocol on the tunnel listener).\n\n")
	}
	fmt.Fprintf(&b, "# 2) Or, with no stream block yet, a complete minimal one (replace 127.0.0.1:8444 with where\n")
	fmt.Fprintf(&b, "#    :%d traffic went before):\n\n", publicPort)
	fmt.Fprintf(&b, "stream {\n")
	fmt.Fprintf(&b, "    map $ssl_preread_server_name $by_sni {\n")
	fmt.Fprintf(&b, "        default  127.0.0.1:8444;\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "    map $remote_addr $tunnel_or_sni {\n")
	for _, ip := range sp.Sources {
		fmt.Fprintf(&b, "        %s  %s;\n", ip, sp.Upstream)
	}
	fmt.Fprintf(&b, "        default  $by_sni;\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "    server {\n")
	fmt.Fprintf(&b, "        listen %d;\n", publicPort)
	fmt.Fprintf(&b, "        ssl_preread on;\n")
	fmt.Fprintf(&b, "        proxy_pass $tunnel_or_sni;\n")
	if sp.ProxyProtocol {
		fmt.Fprintf(&b, "        proxy_protocol on;\n")
	}
	fmt.Fprintf(&b, "    }\n}\n\n")
	fmt.Fprintf(&b, "# Note: the source address is the TCP peer nginx sees, so this only works when clients reach\n")
	fmt.Fprintf(&b, "# nginx directly (not through a CDN or another proxy). If a listed IP changes, update the map.\n")
	fmt.Fprintf(&b, "# Then: nginx -t && systemctl reload nginx\n")
	return b.String()
}

// parseSourceIPs validates a comma separated list of exact IP addresses.
func parseSourceIPs(spec string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address (exact addresses only, no ranges)", part)
		}
		if k := ip.String(); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, nil
}

// haproxyFor renders the HAProxy configuration for a spec.
func haproxyFor(sp frontSpec, publicPort int) string {
	send := ""
	if sp.ProxyProtocol {
		send = " send-proxy"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HAProxy: route the tunnel's SNI to the tunnel listener (TCP passthrough, TLS not terminated)\n")
	fmt.Fprintf(&b, "frontend tls_in\n")
	fmt.Fprintf(&b, "    bind :%d\n", publicPort)
	fmt.Fprintf(&b, "    mode tcp\n")
	fmt.Fprintf(&b, "    tcp-request inspect-delay 5s\n")
	fmt.Fprintf(&b, "    tcp-request content accept if { req_ssl_hello_type 1 }\n")
	if len(sp.Sources) > 0 {
		// Source routing: these addresses go to the tunnel whatever SNI they send, so the
		// tunnel can share an SNI with a real service.
		fmt.Fprintf(&b, "    use_backend hedioum if { src %s }\n", strings.Join(sp.Sources, " "))
	} else {
		fmt.Fprintf(&b, "    use_backend hedioum if { req_ssl_sni -i %s }\n", sp.SNI)
	}
	fmt.Fprintf(&b, "    default_backend web   # your existing backend for everything else\n\n")
	fmt.Fprintf(&b, "backend hedioum\n")
	fmt.Fprintf(&b, "    mode tcp\n")
	fmt.Fprintf(&b, "    server hub %s%s\n", sp.Upstream, send)
	return b.String()
}

// cmdFrontProxy prints the front-proxy configuration for the foreign's own listener.
func cmdFrontProxy(args []string) {
	fs := flag.NewFlagSet("front-proxy", flag.ExitOnError)
	kind := fs.String("kind", "nginx", "front proxy: nginx | haproxy")
	port := fs.Int("public-port", 443, "the public port the front proxy listens on")
	sources := fs.String("source-ips", "", "comma separated exact IPs of the Iran hub(s): route them to the tunnel by source address instead of the SNI, so the tunnel can share an SNI with a real service")
	_ = fs.Parse(args)

	if err := validPort(*port); err != nil {
		fail("--public-port: %v", err)
	}
	if *kind != "nginx" && *kind != "haproxy" {
		fail("--kind must be nginx or haproxy")
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "foreign" {
		fail("no foreign config (run this on the foreign server)")
	}
	sp, err := foreignFrontSpec(cfg)
	if err != nil && !errors.Is(err, errNoSNIListener) {
		fail("%v", err)
	}
	fw := foreignDedicatedForwards(cfg)

	if *sources != "" {
		ips, perr := parseSourceIPs(*sources)
		if perr != nil {
			fail("--source-ips: %v", perr)
		}
		if len(ips) == 0 {
			fail("--source-ips: no addresses given")
		}
		sp.Sources = ips
	}

	color.HiCyan("# Front-proxy configuration (printed only; nothing was changed)\n")
	if err == nil {
		if *kind == "haproxy" {
			fmt.Println(haproxyFor(sp, *port))
		} else {
			fmt.Println(nginxFor(sp, *port))
		}
		printHubHintForForeign(cfg, sp, *port)
	}
	if len(fw) > 0 {
		if *kind == "haproxy" {
			fmt.Println(haproxyDedicated(fw, cfg.ProxyProtocol))
		} else {
			fmt.Println(nginxDedicated(fw, cfg.ProxyProtocol))
		}
		printDedicatedHubHint(fw)
	}
}
