package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// front-proxy prints the nginx / HAProxy configuration that routes a reverse node's SNI
// to its hub listener, so the tunnel and other services (a panel, user configs...) can
// share one public port such as 443. It only prints: it never edits the proxy's files.

// frontProxyUpstream returns the host:port a front proxy should forward the node's
// tunnel traffic to, and the SNI it should match on.
func frontProxyUpstream(node config.ForeignNode) (upstream, sni string, err error) {
	if !node.Reverse || len(node.ReverseListeners) == 0 {
		return "", "", fmt.Errorf("node %q is not in reverse mode; run reverse-iran first", node.Alias)
	}
	l := node.ReverseListeners[0]
	host := node.ReverseBind
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	sni = l.ServerName
	if sni == "" {
		return "", "", fmt.Errorf("node %q has no SNI; re-run reverse-iran with --sni NAME so the proxy can recognise the tunnel", node.Alias)
	}
	return net.JoinHostPort(host, fmt.Sprint(l.Port)), sni, nil
}

// nginxSnippet renders the nginx stream configuration for a node.
func nginxSnippet(node config.ForeignNode, publicPort int) (string, error) {
	up, sni, err := frontProxyUpstream(node)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# nginx (needs the stream and ssl_preread modules)\n")
	fmt.Fprintf(&b, "# 1) If you already have a stream block listening on :%d with ssl_preread, add ONE line\n", publicPort)
	fmt.Fprintf(&b, "#    to its map and keep everything else as it is:\n\n")
	fmt.Fprintf(&b, "    %s  %s;\n\n", sni, up)
	if node.ReverseProxyProtocol {
		fmt.Fprintf(&b, "# This node requires the PROXY protocol, so the stream server that listens on :%d must\n", publicPort)
		fmt.Fprintf(&b, "# have `proxy_protocol on;` (every upstream of that server then receives the header).\n\n")
	} else {
		fmt.Fprintf(&b, "# This node does NOT use the PROXY protocol, so the stream server on :%d must NOT have\n", publicPort)
		fmt.Fprintf(&b, "# `proxy_protocol on;`. If it does (other upstreams need it), re-run reverse-iran with\n")
		fmt.Fprintf(&b, "# --proxy-protocol, which is simpler than a helper server.\n\n")
	}
	fmt.Fprintf(&b, "# 2) Or, with no stream block yet, a complete minimal one (the default upstream is where\n")
	fmt.Fprintf(&b, "#    :%d traffic went before; replace 127.0.0.1:8444 with it):\n\n", publicPort)
	fmt.Fprintf(&b, "stream {\n")
	fmt.Fprintf(&b, "    map $ssl_preread_server_name $backend {\n")
	fmt.Fprintf(&b, "        %s  %s;\n", sni, up)
	fmt.Fprintf(&b, "        default  127.0.0.1:8444;\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "    server {\n")
	fmt.Fprintf(&b, "        listen %d;\n", publicPort)
	fmt.Fprintf(&b, "        ssl_preread on;\n")
	fmt.Fprintf(&b, "        proxy_pass $backend;\n")
	if node.ReverseProxyProtocol {
		fmt.Fprintf(&b, "        proxy_protocol on;\n")
	}
	fmt.Fprintf(&b, "    }\n}\n\n")
	fmt.Fprintf(&b, "# Then: nginx -t && systemctl reload nginx\n")
	return b.String(), nil
}

// haproxySnippet renders the HAProxy configuration for a node.
func haproxySnippet(node config.ForeignNode, publicPort int) (string, error) {
	up, sni, err := frontProxyUpstream(node)
	if err != nil {
		return "", err
	}
	send := ""
	if node.ReverseProxyProtocol {
		send = " send-proxy"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HAProxy: route the tunnel's SNI to the hub listener (TCP passthrough, TLS not terminated)\n")
	fmt.Fprintf(&b, "frontend tls_in\n")
	fmt.Fprintf(&b, "    bind :%d\n", publicPort)
	fmt.Fprintf(&b, "    mode tcp\n")
	fmt.Fprintf(&b, "    tcp-request inspect-delay 5s\n")
	fmt.Fprintf(&b, "    tcp-request content accept if { req_ssl_hello_type 1 }\n")
	fmt.Fprintf(&b, "    use_backend hedioum if { req_ssl_sni -i %s }\n", sni)
	fmt.Fprintf(&b, "    default_backend web   # your existing backend for everything else\n\n")
	fmt.Fprintf(&b, "backend hedioum\n")
	fmt.Fprintf(&b, "    mode tcp\n")
	fmt.Fprintf(&b, "    server hub %s%s\n", up, send)
	return b.String(), nil
}

// cmdFrontProxy prints the front-proxy configuration for a reverse node.
func cmdFrontProxy(args []string) {
	fs := flag.NewFlagSet("front-proxy", flag.ExitOnError)
	alias := fs.String("alias", "", "reverse node alias (required)")
	kind := fs.String("kind", "nginx", "front proxy: nginx | haproxy")
	port := fs.Int("public-port", 443, "the public port the front proxy listens on")
	_ = fs.Parse(args)

	if *alias == "" {
		fail("--alias is required")
	}
	if err := validPort(*port); err != nil {
		fail("--public-port: %v", err)
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Role != "iran" {
		fail("no Iran hub config (run this on the hub)")
	}
	node := findNode(cfg, *alias)
	if node == nil {
		fail("no node with alias %q", *alias)
	}
	var out string
	switch *kind {
	case "nginx":
		out, err = nginxSnippet(*node, *port)
	case "haproxy":
		out, err = haproxySnippet(*node, *port)
	default:
		fail("--kind must be nginx or haproxy")
	}
	if err != nil {
		fail("%v", err)
	}
	color.HiCyan("# Front-proxy configuration for node %q (printed only; nothing was changed)\n", *alias)
	fmt.Println(out)
}
