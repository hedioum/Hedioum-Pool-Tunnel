# Handing outgoing traffic to a local proxy (egress upstream)

By default a foreign node dials every destination itself ("freedom"). With
`egress_upstream` set, it instead hands each TCP stream and each UDP flow to a **SOCKS5
proxy** you run next to it, for example a `socks` or `mixed` inbound of 3x-ui / Xray
listening on `127.0.0.1`. The proxy's own routing rules then decide what goes direct,
what goes through WARP, and which IP family is used.

```
user -> inbound (Iran) -> outbound (Iran) -> hub -> foreign -> 127.0.0.1 inbound -> outbound (foreign)
```

## Turn it on

```
hedioum-tunnel edit-foreign --egress-upstream 127.0.0.1:10808     # SOCKS5, TCP and UDP
hedioum-tunnel edit-foreign --egress-upstream ''                  # back to direct
```

or in the menu: **Advanced Settings -> Outgoing traffic**. Off by default. `socks5://HOST:PORT`
is accepted too. The proxy must accept SOCKS5 **without a password** (bind it to loopback).

## Behaviour

- **Fails closed.** If the proxy is down or refuses, the connection fails. Nothing falls
  back to a direct connection, so traffic meant for WARP never leaves with the server's own
  address.
- **Destination names are passed through.** A hostname is sent to the proxy as a name, so
  domain rules in its routing still match. The foreign resolves it once only to vet it.
- **The SSRF gate stays.** Loopback, private, link-local and CGNAT destinations are still
  refused before the proxy is asked.
- **IP family and source IP** (`egress_ip_mode`, `egress_bind_ip`) no longer apply while an
  upstream is set; the proxy's outbound chooses them.
- **UDP** uses SOCKS5 `UDP ASSOCIATE`. The proxy has to support it (Xray's `socks` / `mixed`
  inbound does when UDP is enabled on it).
- Applies to the normal and the reverse mode alike: it only changes how the foreign reaches the
  internet.
