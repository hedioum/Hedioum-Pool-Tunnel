package main

import (
	"flag"
	"fmt"
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
}

// nginxFor renders the nginx stream configuration for a spec.
func nginxFor(sp frontSpec, publicPort int) string {
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
	fmt.Fprintf(&b, "    use_backend hedioum if { req_ssl_sni -i %s }\n", sp.SNI)
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
	if err != nil {
		fail("%v", err)
	}

	color.HiCyan("# Front-proxy configuration (printed only; nothing was changed)\n")
	if *kind == "haproxy" {
		fmt.Println(haproxyFor(sp, *port))
	} else {
		fmt.Println(nginxFor(sp, *port))
	}
	printHubHintForForeign(cfg, sp, *port)
}
