# Sharing a port with the tunnel (nginx / HAProxy in front)

A reverse-tunnel hub (see [REVERSE.md](REVERSE.md)) has to be reachable from the foreign
on a public port, and the best port is 443. But 443 is usually needed for something else
on the hub too: a panel, user configs, a website. If Hedioum owns 443, nothing else can.

A TCP front proxy solves that. It listens on 443, reads only the TLS **SNI** (it does not
terminate TLS) and forwards each connection to the right place. The tunnel gets its own
SNI; everything else keeps going where it went before.

```
foreign ──443, SNI=cdn.example.com──▶ nginx/HAProxy ──▶ 127.0.0.1:8443  (hub listener)
users   ──443, SNI=anything else ───▶ nginx/HAProxy ──▶ your panel / xray / website
```

Rules of thumb:

- The proxy must **pass TCP through** (nginx `stream` + `ssl_preread`, HAProxy `mode tcp`).
  The tunnel does its own TLS and authentication; terminating TLS in the proxy breaks it.
- The tunnel's SNI must not be a name your other services use, otherwise the proxy cannot
  tell them apart. Any name works (it needs no DNS record and no certificate), e.g. a
  sub-domain-looking label next to the SNIs you already use.
- One SNI maps to one listener, so behind a proxy a node serves one mimic type.

## Setting it up from the CLI

```
hedioum-tunnel reverse-iran --alias NAME \
    --ports https-alt=8443 \
    --advertise-ports https-alt=443 \
    --sni cdn.example.com \
    --bind 127.0.0.1 \
    [--proxy-protocol]
```

- `--ports` is where the hub **listens** (a free local port).
- `--advertise-ports` is where the foreign is told to **dial** (the proxy's public port).
  Only the advertised mimic types are served.
- `--sni` is the name the foreign sends and the hub's certificate is issued for.
- `--bind 127.0.0.1` keeps the listener off the public interface, so it is only reachable
  through the proxy (the host firewall then opens nothing for it).
- `--proxy-protocol` makes the listener require a PROXY protocol header (v1 or v2), for a
  proxy that adds one (nginx `proxy_protocol on;`, HAProxy `send-proxy`). Connections
  without a header are dropped. Use it when the proxy's stream server already uses the
  PROXY protocol for its other upstreams.

These settings are remembered per node; a later `reverse-iran --alias NAME` keeps them
unless you pass the flags again (`--advertise-ports ""` / `--bind ""` clear them). The same
questions are asked in the interactive menu ("Reverse Tunnel: Switch a Node ..." >
"Through a reverse proxy").

Print the proxy configuration for a node (it only prints, it never edits your files):

```
hedioum-tunnel front-proxy --alias NAME --kind nginx      # or haproxy
```

Then `nginx -t && systemctl reload nginx`, and run the `reverse-foreign --token ...` line
`reverse-iran` printed on the foreign.

## nginx

If you already have a `stream` block listening on 443 with `ssl_preread on;`, add one line
to its `map`:

```
map $ssl_preread_server_name $backend {
    cdn.example.com   127.0.0.1:8443;    # the tunnel
    app.example.com   127.0.0.1:10001;   # what was already there
    default           127.0.0.1:10001;
}
```

PROXY protocol must match on both sides: if that stream server has `proxy_protocol on;`
(each upstream then receives the header), use `--proxy-protocol` on the node. If it does
not, leave the flag off.

## HAProxy

```
frontend tls_in
    bind :443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    use_backend hedioum if { req_ssl_sni -i cdn.example.com }
    default_backend web

backend hedioum
    mode tcp
    server hub 127.0.0.1:8443 send-proxy     # drop send-proxy if the node has no --proxy-protocol
```

## Going back

`reverse-iran --alias NAME --advertise-ports "" --bind "" --proxy-protocol=false` returns
the node to direct listeners; `--forward` leaves reverse mode altogether and clears these
settings.
