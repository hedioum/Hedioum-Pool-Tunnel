# Sharing a port with the tunnel (nginx / HAProxy in front)

The side of the tunnel that **listens** needs a public port, and the best port is 443.
But 443 is usually needed for something else on the same server too: a panel, user
configs, a website. If Hedioum owns 443, nothing else can.

- In the default (direct) mode the **foreign** egress listens and the Iran hub dials it.
- In [reverse mode](REVERSE.md) the **Iran hub** listens and the foreign dials it.

Either listener can sit behind a TCP front proxy. The proxy owns 443, reads only the TLS
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

The same four settings apply on both sides:

| setting | what it does |
| --- | --- |
| listen port | where the tunnel listener binds (a free local port, e.g. 8443) |
| advertise port | the port the dialer is told to use (the proxy's public port, 443) |
| bind `127.0.0.1` | keeps the listener off the public interface; the host firewall opens nothing for it |
| PROXY protocol | the listener requires a PROXY header (v1/v2) from a proxy that sends one (nginx `proxy_protocol on;`, HAProxy `send-proxy`); connections without one are dropped |

These are remembered; a later edit keeps them unless you change them. `front-proxy`
prints the proxy configuration (it only prints, it never edits your files); the
interactive menu asks the same questions.

## In the interactive menu

Everything below can be set without remembering flags. Hub menu: **12. Advanced Settings**;
foreign menu: **9. Advanced Settings**. Each entry shows whether it is ON or OFF and is off
unless you turn it on:

- Hub: front proxy for normal nodes (the port and SNI the hub dials), front proxy for
  reverse nodes (turn on or off, or print the nginx / HAProxy config, optionally routed by
  the foreign's IP), and the shared reverse listener switch.
- Foreign: front proxy (public port, local listener port, SNI, PROXY protocol, loopback
  bind), the pairing token for the hub, and the reverse hubs with their pipe ranges.

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

Menu: **Front Proxy: share a port such as 443 with nginx / HAProxy**.

## Iran hub (reverse mode)

```
hedioum-tunnel reverse-iran --alias NAME \
    --ports https-alt=8443 --advertise-ports https-alt=443 \
    --sni cdn.example.com --bind 127.0.0.1 [--proxy-protocol]
hedioum-tunnel front-proxy --alias NAME --kind nginx
```

Run the printed `reverse-foreign --token ...` line on the foreign. Menu: **Reverse Tunnel:
Switch a Node Normal <-> Reverse** > "Through a reverse proxy".

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

## Sharing an SNI with a real service (route by source IP)

SNI routing needs the tunnel to have its own SNI. If you want the tunnel on the **same**
name as a real service on that port (say `i1.example.com`, which also carries user
configs), the proxy cannot tell them apart by SNI. It can tell them apart by who connects:
the tunnel's peers are your own servers, with known addresses. `front-proxy --by-source`
prints a configuration that sends those addresses to the tunnel listener whatever SNI they
present, while every other client keeps following the SNI map exactly as before.

```
# hub (reverse mode): the node's foreign IP, plus any node sharing its listener
hedioum-tunnel front-proxy --alias NAME --by-source
# or name the addresses yourself (a foreign lists the hub IP instead)
hedioum-tunnel front-proxy --alias NAME --source-ips 203.0.113.10,203.0.113.20 --kind haproxy
```

For nginx this is a second `map $remote_addr $tunnel_or_sni` whose default is your existing
SNI map; HAProxy gets `use_backend hedioum if { src ... }` ahead of the SNI rules. Only exact
addresses are accepted. The source address is the TCP peer the proxy sees, so it only works
when clients reach the proxy directly (not through a CDN), and a listed address that changes
has to be updated in the proxy. The tunnel's TLS and token authentication are untouched.

## Going back

Foreign: `edit-foreign --advertise-ports "" --bind "" --proxy-protocol=false`. Hub:
`reverse-iran --alias NAME --advertise-ports "" --bind "" --proxy-protocol=false`
(or `--forward` to leave reverse mode, which clears the settings).
