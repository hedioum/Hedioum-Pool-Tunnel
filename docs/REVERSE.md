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
  current endpoint ports; pass `--ports` if one is already in use on the hub (two reverse
  nodes on one hub need distinct ports).
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
- **Diagnostics.** `probe` and `speedtest` open their own connection to the foreign and do
  not apply to a reverse node (they say so); `test` still runs the end-to-end SOCKS egress
  checks. Look for `reverse pipe established` in `journalctl -u hedioum.service` on both
  ends.
- **Config.** Reverse nodes add `reverse` / `reverse_listeners` to a hub node and
  `reverse_targets` / `reverse_conns` / `reverse_only` to the foreign config. Existing
  configs and pairing tokens load unchanged.
