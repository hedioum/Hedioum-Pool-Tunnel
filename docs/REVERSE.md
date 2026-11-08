# Reverse tunnel (foreign dials the hub)

By default the Iran hub dials the foreign egress. On some paths that direction is
filtered: the TCP connection opens but the TLS/SSH handshake from the hub to a
particular foreign IP never completes (the IP shows up "grey"), while the opposite
direction — the foreign opening the connection towards Iran — works fine.

**Reverse mode flips only who opens the TCP connection.** Everything else is the same
pair of nodes: same token, same SOCKS port, same TUN/gateway settings, same mimic set,
same bandwidth profile, same lifecycle/churn rules. The hub still opens every logical
stream and the foreign still serves it, so TCP, UDP, DNS (resolved on the foreign) and
the SSRF policy behave exactly as before.

```
forward (default):   hub ──dials──▶ foreign          hub opens streams, foreign serves them
reverse:             hub ◀──dials── foreign          hub opens streams, foreign serves them
```

## Switching an existing pair

Everything below is also available from the interactive menu (`hedioum-tunnel`): on the
hub, **Reverse Tunnel: Switch a Node Normal <-> Reverse** (pick the node, review or edit
the listener ports, and it prints the token for the foreign); on the foreign,
**Reverse Mode: Dial the Hub** (paste the token). The commands:

On the **hub** (flips the node and prints the command for the foreign):

```
hedioum-tunnel reverse-iran --alias DE-01
# optional: --ports tls=443,https-alt=8443   --public-ip 198.51.100.10
```

On the **foreign**, paste what the hub printed:

```
hedioum-tunnel reverse-foreign --token <REVERSE_TOKEN>
# optional: --conns 30   (pipes to keep open; default 12)
#           --keep-listeners   (also keep the normal inbound listeners)
```

By default the foreign then runs **dial-out only**: it opens no listener, no
certificate and no decoy, and `--open-firewall` skips it. The hub opens its listener
ports in the host firewall on start (they must also be reachable from the foreign in
any provider/network firewall).

Switch back at any time:

```
hedioum-tunnel reverse-iran --alias DE-01 --forward     # on the hub
hedioum-tunnel reverse-foreign --forward                # on the foreign
```

## Details

- **Mimics.** The hub listens with the node's own mimic set (so both ends keep the same
  camouflage), minus `ssh`: an SSH mimic needs a real `sshd` as its decoy and port 22 is
  normally taken on the hub. Any TLS/STARTTLS mimic (`tls`, `https-alt`, `smtps`, `imaps`,
  `smtp`, `imap`, `cpanel`, …) works. Unauthorized probes on a hub listener get the same
  decoy a probe on a foreign listener gets. By default the listeners use the node's
  current endpoint ports; a port that is already taken on the hub (another service, or
  another reverse node) is replaced by a free one automatically and reported. Pass
  `--ports` to choose them yourself (an explicit port that is taken is an error).
- **Camouflage carries over.** The SNI the foreign sends (from the node's endpoints, or
  `--sni`) is also the name the hub's listener certificate is issued for, and the decoy
  shown to unauthorized probes can mirror the foreign's (`--decoy-style apache|directadmin`,
  default: the hub's own). Both are also asked in the interactive menu. Run
  `reverse-iran --alias NAME --sni <the foreign's SNI> --decoy-style <the foreign's style>`
  to make the hub look like the foreign it stands in for.
- **Sharing a port (nginx / HAProxy in front).** To keep 443 for a panel or other services
  and still run the tunnel on it, route the tunnel's SNI to the hub listener with a TCP
  front proxy; see [FRONT_PROXY.md](FRONT_PROXY.md) (`--advertise-ports`, `--bind`,
  `--proxy-protocol`, and the `front-proxy` command that prints the proxy config).
- **Certificate.** Self-signed by default. Set `domain` (and optionally `acme_email`) in
  the hub config to serve a real Let's Encrypt certificate, as the foreign does.
- **Authentication.** Unchanged and mutual: the foreign proves the token to the hub and the
  hub proves it back before any stream is accepted, so a rogue listener cannot use the
  foreign as an exit.
- **Pool sizing.** The foreign keeps `--conns` pipes open (default 12 = 10 TCP + the 2 the
  hub dedicates to its UDP sub-pool). The hub caps active TCP pipes at the node's
  `max_connections`. Because only the foreign dials, the pool does **not** scale up under
  load the way forward mode does: raise `--conns` for more throughput. Retiring pipes
  (the usual lifecycle churn) are replaced automatically by the foreign redialling.
- **Several hubs per foreign.** One reverse foreign can dial more than one Iran hub, each
  with its own pipe range, because the foreign is the side that dials:

  ```
  hedioum-tunnel add-hub --token <TOKEN from reverse-iran on that hub> --name ir2 --min 4 --max 16
  hedioum-tunnel edit-hub --name ir2 --max 24
  hedioum-tunnel list-hubs
  hedioum-tunnel remove-hub --name ir2
  ```

  The foreign always keeps `--min` pipes open to a hub and opens more, up to `--max`, while
  the open streams per pipe stay high (about 6 or more); an idle pipe above `--min` is
  closed after a few quiet minutes. Without `--max` the pool is fixed at `--min`
  (default 12). Keep the hub node's `max_connections` at or above `--max`, otherwise the hub
  drops the extra pipes (the foreign cools that endpoint down instead of redialling in a
  loop). Bandwidth and jitter shaping stay on each hub's node (`edit-node` there), so every
  hub has its own. A hub may know the foreign by a different token than the foreign's own;
  the token inside the pairing token is then stored for that hub only. A foreign with a
  single hub keeps `reverse_targets` / `reverse_conns` and behaves as before; adding a
  second hub promotes it to a hub named `default`. `reverse-foreign --forward` clears all
  hubs.
- **Several foreign servers on one listener (advanced, off by default).** Normally every
  reverse node needs its own listener port, because a node's listener only knows that
  node's token. With `shared_reverse_auth` on, nodes whose listener has the same bind
  address, port, type, SNI and PROXY protocol setting share one socket, and the hub tells
  them apart by which node token authenticates the handshake (the handshake itself is
  unchanged: the client's HMAC is checked against each node token, and the pipe is adopted
  by the node that matched). This is what lets one SNI behind a front proxy carry several
  foreign servers.

  ```
  hedioum-tunnel reverse-shared-auth --on
  hedioum-tunnel reverse-iran --alias A --sni t.example.com ...        # first node, as usual
  hedioum-tunnel reverse-iran --alias B --share-with A                  # B joins A's listener
  hedioum-tunnel reverse-shared-auth --off                              # refused while any listener is shared
  ```

  The shared listener serves a single decoy and certificate (A's SNI). The SSH mimic cannot
  be shared.
- **Diagnostics.** `probe` and `speedtest` open their own connection to the foreign and do
  not apply to a reverse node (they say so); `test` still runs the end-to-end SOCKS egress
  checks. Look for `reverse pipe established` in `journalctl -u hedioum.service` on both
  ends.
- **Config.** Reverse nodes add `reverse` / `reverse_listeners` to a hub node and
  `reverse_targets` / `reverse_conns` / `reverse_only` (and optionally `reverse_hubs`) to the
  foreign config, and an optional `shared_reverse_auth` to the hub. Existing configs and
  pairing tokens load unchanged.
