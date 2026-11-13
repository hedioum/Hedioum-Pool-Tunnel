# Hedioum Dynamic Pool Tunnel (Chaos Mesh)

[![Downloads](https://img.shields.io/github/downloads/hedioum/Hedioum-Pool-Tunnel/total?color=brightgreen&label=downloads)](https://github.com/hedioum/Hedioum-Pool-Tunnel/releases)
[![Latest release](https://img.shields.io/github/v/release/hedioum/Hedioum-Pool-Tunnel?color=blue&label=release)](https://github.com/hedioum/Hedioum-Pool-Tunnel/releases/latest)
[![Stars](https://img.shields.io/github/stars/hedioum/Hedioum-Pool-Tunnel?style=flat)](https://github.com/hedioum/Hedioum-Pool-Tunnel/stargazers)

🌐 **🇬🇧 English** · **[🇮🇷 فارسی](README.fa.md)** · **[🇷🇺 Русский](README.ru.md)** · **[🇨🇳 中文](README.zh.md)** · **[Latest release](https://github.com/hedioum/Hedioum-Pool-Tunnel/releases/latest)**

Hedioum Pool Tunnel is a high-performance, enterprise-grade connection multiplexer designed to bypass strict Deep Packet Inspection (DPI) and thwart TCP Meltdown under heavy load. It operates as a Custom SDN Overlay, wrapping encrypted VLESS/Trojan traffic into highly obfuscated, dynamically scaling connection pools that wear a **16-mimic arsenal** of interchangeable disguises — **SSH, TLS/HTTPS, mail (SMTP/IMAP/SMTPS/IMAPS), databases (PostgreSQL/MySQL), and hosting/devops panels (cPanel, WHM, Webmail, DirectAdmin, Docker Registry, Grafana, Prometheus)** — assembled into coherent server **personas**, over a modern authenticated-encryption transport. It also exposes an optional OS-level **TUN interface** and a **transparent gateway mode**, and runs **on MikroTik/RouterOS and in Docker** — routing a whole LAN through the disguised tunnel with no per-device change.

## 🌟 Key Features

- **Chaos Mesh Dynamic Balancing:** Replaces traditional Round-Robin with a smart "Least Loaded" distribution algorithm. The system actively monitors real-time bandwidth (Mbps) and scales physical connections up or down based on actual traffic volume, not just stream count.
- **DPI Evasion (Fluctuating Caps):** Implements dynamic bandwidth jitter. Each physical connection operates under a randomized, fluctuating bandwidth limit (e.g., 8 Mbps ± 2 Mbps) to break static patterns, making the tunnel indistinguishable from organic, noisy internet traffic.
- **Zero-Downtime Connection Draining:** During scale-down events, idle physical connections are placed in a `Draining` state. They wait for active logical streams (like open socket connections) to finish naturally before closing, ensuring zero lag or disconnections for end-users.
- **Enterprise Lifecycle Management:** Features an interactive TUI dashboard equipped with a Blue-Green Self-Updater (with automatic rollback on failure) and a Clean Uninstaller that purges all traces without leaving orphaned files.
- **Authenticated Encryption (ChaCha20-Poly1305):** The transport is wrapped in a modern AEAD stream keyed via HKDF from your token. ChaCha20 needs no AES-NI, so overhead stays minimal on cheap/ARM VPS. The token is never sent on the wire and also keys the cipher, so a passive observer sees only random salts followed by ciphertext.
- **Real Certificate (Let's Encrypt) or DirectAdmin Persona:** Point a domain at the foreign node (`--domain`) and the TLS mimic serves a genuine, **auto-renewing Let's Encrypt certificate** (ACME) — CT-logged like any real HTTPS host, with a DNS A/AAAA pre-check, a self-healing warm-and-renew loop, and a graceful self-signed fallback so a certificate hiccup can never break the tunnel. Without a domain, a self-signed cert is used. Optionally the node wears a **DirectAdmin control-panel persona**: a pixel-faithful DirectAdmin *Evolution* login (light + dark mode, real assets embedded in the binary) on **:2222**, where a self-signed certificate is authentic — and the web ports answer exactly like a real DirectAdmin box.
- **Protocol-Aware Connection Lifecycle:** After raw volume, the strongest real-world tunnel tell is *protocol × connection lifetime*. SSH is the trusted long-lived backbone (rotating on a randomized multi-hour schedule); every non-SSH mimic is auxiliary with a **randomized 5–60 min lifetime + 1–5 GB transfer budget**, then it drains and the pool churns to a fresh pipe with a new random mimic. Each server's timings are seeded from its secret token, so no two servers churn alike.
- **Full TCP + UDP:** A single local SOCKS5 port serves both TCP (CONNECT) and UDP (ASSOCIATE), so QUIC/HTTP3, DNS, and voice/video calls work. UDP rides its own dedicated (still SSH-masked) connection sub-pool, isolated from TCP so a bulk download can't stall a call, with drop-on-congestion so a slow link never buffers unboundedly. UDP never touches the wire between the nodes — it is tunnelled over the masked TCP link.
- **Optional IPv6:** The inter-node link and egress-to-internet can use IPv6 (`egress_ip_mode`: `ipv4` default / `ipv6` / `dual`), opt-in so the server's IPv6 identity is never leaked by default.
- **Opt-in TUN mode + leak-free DNS:** Besides the SOCKS5 port, each node can expose an OS-level **TUN interface** (`--tun`) so the tunnel is usable as a plain network interface, plus a **`:53` DNS forwarder** (`--dns`) that resolves through the tunnel (no local leak). It is per-node (own interface + `/24`), opt-in, and **never becomes the host default route** — so the hub's own egress and SSH stay direct. The TUN engine (a gVisor userspace stack over the node's SOCKS) needs no external `ip` binary, so it works inside a `FROM scratch` container.
- **Transparent Gateway mode (route a whole LAN):** with `--gateway`, a hub — especially a single container on **MikroTik/RouterOS** or any Linux router — becomes a transparent L3 gateway: LAN devices keep the router as their gateway, you **mark + route** the traffic you want tunneled to the container (exactly the WireGuard/L2TP pattern), and it forwards a whole LAN through the disguised tunnel — **no per-device change and no external proxy**. Built on the TUN engine; routing via netlink (`iif` rule + `ip_forward`) with a RouterOS-7.22 guard. **Validated end-to-end on a real RouterOS CHR and a plain Linux router** (LAN client's exit IP = the foreign, TCP+UDP, no DNS leak, no lock-out).
- **Runs on MikroTik / in Docker:** ships as a tiny multi-arch (`amd64/arm64/armv7`) `FROM scratch` image (~17 MB) at `ghcr.io/hedioum/pool-tunnel`, **verified running inside a RouterOS container with TUN + gateway mode working** — see the step-by-step **[MikroTik guide](docs/MIKROTIK.md)**.
- **Pluggable Protocol Mimicry — 16-mimic arsenal:** A single node listens behind many camouflages at once. **SSH** (real SSH-2.0 banner mirrored byte-for-byte from the host's own `sshd`); **implicit-TLS** on **TLS/HTTPS**, **HTTPS-alt (:8443)**, **SMTPS/IMAPS (465/993)**, a **Docker Registry (:5000)**, **Grafana (:3000)**, **Prometheus (:9090)**, and the **cPanel / WHM / Webmail** panels (`:2083/2087/2096`, real `cpsrvd` server header and pixel-faithful login pages); **STARTTLS** on **SMTP/IMAP (587/143)**, **PostgreSQL (:5432)** and **MySQL (:3306)** (genuine protocol prologues — `SSLRequest`, a MySQL v10 greeting — before the TLS upgrade); and a **DirectAdmin** panel (`:2222`). The hub spreads its physical pipes across them with a **per-install fluctuating distribution** (Chaos Mesh v2), so two servers running the same build present different, shifting on-wire signatures. Every mimic routes unauthorized probes to a protocol-appropriate decoy — the real `sshd`, a real panel login, or a web persona whose `Server`/`ETag`/`Last-Modified` are **per-install unique** (seeded from the token, no fleet-wide signature). A plaintext decoy on **`:80`** makes even the bare IP look like an ordinary web host to reputation scanners. See **[docs/MIMICS.md](docs/MIMICS.md)**.
- **Coherent Server Personas:** Instead of a random mimic mix, a node can wear a **persona** — a self-consistent identity that real admins would recognize: **`cpanel`** (TLS + cPanel/WHM/Webmail), **`directadmin`** (TLS + DirectAdmin), or **`devops`** (TLS + HTTPS-alt + Docker + Grafana + Prometheus). Each persona is **SSH + 9 coherent mimics**, seeded deterministically from the node's token (so the hub can re-derive the exact same set from the shared token), with a coherence rule so incompatible panels never co-appear. Pick one with `--persona cpanel|directadmin|devops`, or `--persona auto`.
- **Paste-only onboarding (v2 pairing token):** `setup-foreign` prints a single self-contained **pairing token** (base64url) that already carries the exit IP, every mimic→port mapping, the persona and the auth key — so the hub is onboarded by pasting one string: `setup-iran --token <PAIRING_TOKEN> --socks-port 40001`. No `--target-ip`/`--mimics`/`--persona` to match by hand.
- **Multi-port connect-race:** the hub dials a node across all its mimic ports with a weighted, innocuous-first race and per-endpoint reachability memory (cooldown/backoff), so if one port (e.g. `:22`) is blocked or throttled on your path, the tunnel still comes up over the others and recovers automatically.
- **No DNS Leak by Design:** the SOCKS5 ingress forwards the destination **domain** (never a locally-resolved IP) through the tunnel, so DNS is resolved on the **foreign** node — configure your client for remote DNS (`domainStrategy: AsIs`) and the Iran box emits no DNS query for tunneled destinations. See the verification steps in [docs/MIMICS.md](docs/MIMICS.md).
- **Channel-Bound Token Auth (no double crypto):** The TLS mimic authenticates the peer with an HMAC bound to the server's live certificate fingerprint — proving knowledge of the token *without ever sending it* and defeating MITM — while keeping a **single** crypto layer (the TLS session itself) for uniform, high-throughput performance. The client uses **uTLS** (a real Chrome ClientHello) to defeat JA3 fingerprinting.
- **Throughput Engineering:** BBR congestion control + `fq` qdisc are enabled on install, Yamux stream windows are widened to 16 MB for high bandwidth-delay-product links, and a built-in `speedtest` command measures real end-to-end egress throughput (un-shaped) per endpoint.
- **Share port 443 with a front proxy (nginx / HAProxy):** the foreign listener can sit behind a TCP front proxy that routes by SNI, so the tunnel and your panel / user configs / website share one public port. `edit-foreign --ports … --advertise-ports TYPE=443 --bind 127.0.0.1 [--proxy-protocol]` and `front-proxy` (prints the nginx or HAProxy config). See **[docs/FRONT_PROXY.md](docs/FRONT_PROXY.md)**.
- **Reverse tunnel (foreign dials the hub):** when the hub→foreign handshake is filtered (a "grey" foreign IP) but foreign→hub works, flip an existing pair with one command on each side — `reverse-iran --alias NAME` then `reverse-foreign --token …`. Same token, SOCKS port, TUN/gateway, mimics and lifecycle; only who opens the TCP connection changes (the hub still opens every stream). `--forward` flips back. See **[docs/REVERSE.md](docs/REVERSE.md)**.

## 🏗 Architecture Topology

1. **X-UI (Iran):** Authenticates the user, splits domestic traffic, and forwards international traffic to the local SOCKS5 Bridge.
2. **Hedioum Hub (Iran):** Receives the SOCKS5 payload, evaluates pool health, and multiplexes the stream (via HashiCorp Yamux) over an authenticated, encrypted physical connection pool using the Chaos Mesh algorithm.
3. **Hedioum Egress (Foreign):** Authenticates the Hub via the channel-bound handshake (unauthenticated probes are diverted to a protocol-appropriate decoy — the real `sshd`, or a plausible web page for the TLS/mail mimics), enforces SSRF protections (resolve-once, blocks private/link-local/CGNAT), resolves the destination DNS here (no leak in Iran), and dials the open internet over IPv4/IPv6/dual per `egress_ip_mode`.

## 🚀 Installation & Updates

The binary is self-sufficient: it installs its own systemd service, opens the
firewall, and manages its config — so `install.sh` is just a thin bootstrap
(detect architecture → download → run the binary). See **[docs/DEPLOY.md](docs/DEPLOY.md)** for the full guide, including non-interactive (Ansible-friendly) setup and the GitHub-blocked path.

**Installation Order:** install the **Foreign (egress)** node first to generate the auth token the Iran node needs.

### One-line bootstrap (GitHub reachable)
Run on each VPS as root (foreign first):

    bash <(curl -fsSL https://raw.githubusercontent.com/hedioum/Hedioum-Pool-Tunnel/main/install.sh)

### Manual (GitHub blocked)
Copy the matching binary (`hedioum-tunnel` / `hedioum-tunnel-arm64`) to the server, then:

    chmod +x hedioum-tunnel && ./hedioum-tunnel install && hedioum-tunnel

### Non-interactive (automation)

    hedioum-tunnel install
    hedioum-tunnel setup-foreign --persona auto --move-ssh --domain vpn.example.com   # foreign; prints a pairing token
    hedioum-tunnel setup-iran   --alias DE-01 --token <PAIRING_TOKEN> --socks-port 40001   # paste the token; add --tun --dns to expose a TUN interface
    systemctl start hedioum.service

`--persona auto|cpanel|directadmin|devops` picks a coherent identity (SSH + 9 mimics);
`--mimics all` (or a comma list) still works for an explicit set. `setup-foreign` prints a
self-contained **pairing token** — paste it into `setup-iran` and the exit IP, ports and
persona are configured for you (no `--target-ip`/`--mimics` needed). `--domain` is optional
(a real Let's Encrypt cert once DNS points at the node; self-signed otherwise). Add `--tun`
(and `--dns`) on the hub to expose a TUN interface + a leak-free `:53` resolver. Updates are
rollback-safe (`hedioum-tunnel update`, or `update --file <path>` when GitHub is blocked).

**Editing a node in place** (only the flags you pass change; the token is kept unless
`--token`/`--rotate-token`):

    hedioum-tunnel edit-foreign --tls-port 2087 --decoy-style directadmin   # on the foreign
    hedioum-tunnel edit-node --alias DE-01 --bw 12                          # on the Iran hub

### Diagnostics

    hedioum-tunnel probe     --node DE-01                 # per-mimic reachability of every endpoint (hub)
    hedioum-tunnel speedtest --node DE-01 --mimic tls     # real un-shaped egress throughput (hub)
    hedioum-tunnel check-ip                               # egress IP reputation: CLEAN / LIKELY-FLAGGED (foreign)

## ⚙️ Management Dashboard

To manage servers, view live connection status, or perform lifecycle operations, run the interactive dashboard from your terminal at any time:

    hedioum-tunnel

**Dashboard Capabilities:**
- View active egress pools, per-node endpoints (mimic → target), and live DPI Evasion dynamics (Limits & Jitter).
- Monitor real-time daemon logs for Scale-Up/Down events and bandwidth usage.
- Add, **Edit**, or Remove foreign egress nodes dynamically (edit pre-fills each field with its current value — press Enter to keep it), and **Edit the foreign configuration** in place.
- Run a **Speedtest** or **Probe** endpoints (per-mimic reachability) straight from the menu.
- Perform a safe Self-Update (fetches latest GitHub release).
- Completely Uninstall and purge the daemon.

## 🐳 Docker & MikroTik

Hedioum ships as a tiny multi-arch (`amd64/arm64/armv7`) `FROM scratch` image (~17 MB) at
`ghcr.io/hedioum/pool-tunnel`. Run the hub in a container:

    docker run -d --name hedioum --restart unless-stopped \
      --cap-add NET_ADMIN --device /dev/net/tun \
      -v /etc/hedioum:/etc/hedioum ghcr.io/hedioum/pool-tunnel:latest

(SOCKS-only needs neither the cap nor the device.) Write the config first with a one-off
run, e.g. `docker run --rm -v /etc/hedioum:/etc/hedioum ghcr.io/hedioum/pool-tunnel:latest
setup-iran --alias FR --token <PAIRING_TOKEN> --socks-port 40001 --tun --dns`. The image has
no shell, but you still run any subcommand via `docker exec hedioum hedioum-tunnel test
--node FR` (speedtest, probe, edit-node, …); after a config edit, `docker restart hedioum`
to apply.

**On MikroTik/RouterOS** the same image runs inside a RouterOS container — with TUN and
**gateway mode** working. Turn on `--gateway`, then on the router just `mark` the traffic and
`route` it to the container's veth IP to send a **whole LAN** through the tunnel (no per-device
change). Full step-by-step from a bare router: **[docs/MIKROTIK.md](docs/MIKROTIK.md)**.

## 🛠 Building from Source

If you wish to compile the static binary manually:

    git clone https://github.com/hedioum/Hedioum-Pool-Tunnel.git
    cd Hedioum-Pool-Tunnel
    make build-linux

## ☕ Support & Donate

If you found this project helpful for maintaining a free and open internet, and you want to support further development, consider buying the team a coffee!

**USDT (Tether) Donation Addresses:**
- **TRC20 (Tron):** TRhwZFoHRZ9oux4emFXTj63aib9nuC2J2J
- **BEP20 (BSC):** 0x051e31cb70076854C0b62F816d5a89D3def4A22E
- **ERC20 (Ethereum):** 0x051e31cb70076854C0b62F816d5a89D3def4A22E
- **TON (The Open Network):** UQCqq0wYNDVhq9AXAZ5vOQ2ZgMmP6O0UTgvU1YhNeIpkUp1s

Thank you for your support!