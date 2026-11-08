# Sharing a port with the tunnel (nginx / HAProxy in front)

The foreign egress listens and the Iran hub dials it, and the best port for that is 443.
But 443 is usually needed for something else on the same server too: a panel, user
configs, a website. If Hedioum owns 443, nothing else can.

The foreign listener can sit behind a TCP front proxy. The proxy owns 443, reads only the TLS
**SNI** (it does not terminate TLS) and forwards each connection to the right place. The
tunnel gets its own SNI; everything else keeps going where it went before.

```
dialer ──443, SNI=cdn.example.com──▶ nginx/HAProxy ──▶ 127.0.0.1:8443  (tunnel listener)
users  ──443, any other SNI───────▶ nginx/HAProxy ──▶ your panel / xray / website
```

Rules of thumb:

- The proxy must **pass TCP through** (nginx `stream` + `ssl_preread`, HAProxy `mode tcp`).
  The tunnel does its own TLS and authentication; terminating TLS in the proxy breaks it.
- The tunnel's SNI must not be a name your other services use, otherwise the proxy cannot
  tell them apart. Any name works (it needs no DNS record and no certificate).
- One SNI maps to one listener, so behind a proxy a server fronts one mimic type per
  public port. SSH cannot be routed by SNI.

Four settings on the foreign:

| setting | what it does |
| --- | --- |
| listen port | where the tunnel listener binds (a free local port, e.g. 8443) |
| advertise port | the port the hub is told to dial (the proxy's public port, 443) |
| bind `127.0.0.1` | keeps the listener off the public interface; the host firewall opens nothing for it |
| PROXY protocol | the listener requires a PROXY header (v1/v2) from a proxy that sends one (nginx `proxy_protocol on;`, HAProxy `send-proxy`); connections without one are dropped |

These are remembered; a later edit keeps them unless you change them. `front-proxy`
prints the proxy configuration (it only prints, it never edits your files); the
interactive menu asks the same questions.

## Foreign (direct mode)

```
hedioum-tunnel edit-foreign --tls-servername cdn.example.com \
    --ports tls=8443 --advertise-ports tls=443 --bind 127.0.0.1 [--proxy-protocol]
hedioum-tunnel front-proxy --kind nginx          # config for this foreign
hedioum-tunnel pairing-token                     # new paste-only token (advertised ports)
```

On the Iran hub point the existing node at the proxy, or add it with the new token:

```
hedioum-tunnel edit-node --alias NAME --ports tls=443 --tls-servername cdn.example.com
```

Menu: **Advanced Settings** (foreign menu 7) > **Front proxy**, shown as ON or OFF. It asks for the proxy's public port, the local port the tunnel listens on, the SNI, whether the proxy sends the PROXY protocol, and whether to bind to 127.0.0.1.

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
(each upstream then receives the header), enable the PROXY protocol on the tunnel listener
too. If it does not, leave it off. Then `nginx -t && systemctl reload nginx`.

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
    server hub 127.0.0.1:8443 send-proxy     # drop send-proxy if the listener has no PROXY protocol
```

## Going back

`edit-foreign --advertise-ports "" --bind "" --proxy-protocol=false`, then point the hub
node back at the listener port (`edit-node --ports TYPE=PORT`). The menu entry has a
"Remove the front-proxy settings" choice.
