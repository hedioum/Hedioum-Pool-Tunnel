# Hedioum Dynamic Pool Tunnel (Stealth Mesh)

Hedioum Pool Tunnel is a high-performance, enterprise-grade connection multiplexer designed to bypass strict Deep Packet Inspection (DPI) and thwart TCP Meltdown under heavy load. It operates as a Custom SDN Overlay, wrapping encrypted VLESS/Trojan traffic into highly obfuscated, dynamically scaling SSH-mimicked connection pools.

## 🌟 Key Features

- **Zero Double-Encryption Overhead:** Pipes natively encrypted X-UI traffic without re-encrypting with AES, keeping CPU usage near zero on low-end servers.
- **Dynamic Connection Pooling:** Auto-scales physical TCP connections from 5 to 15 based on load, distributing logical streams using Round-Robin. If one packet drops on a single route, the rest of the pool continues streaming flawlessly.
- **Protocol Mimicking:** Accurately simulates the SSH-2.0-OpenSSH handshake and binary framing, coupled with cryptographically secure random noise padding to obscure metadata.
- **Distributed Ingress Mesh:** Allows multiple Iran Hubs (Ingress) to securely funnel traffic into a single or multiple Foreign Egress Nodes.
- **SSRF & Scanner Protection:** In-memory ban-lists for unauthorized active probers and strict blocking of local/private IP dialing on the egress node.

## 🏗 Architecture Topology

1. X-UI (Iran): Authenticates the user, splits domestic traffic, and forwards international traffic to the local SOCKS5 Bridge.
2. Hedioum Hub (Iran): Receives SOCKS5 payload, extracts destination metadata, multiplexes the stream (via HashiCorp Yamux) over an SSH-mimicked physical connection pool.
3. Hedioum Egress (Foreign): Validates the SSH handshake token, extracts target metadata, and dials the open internet directly.

## 🚀 Installation & Seamless Updates

You can deploy or update the Hedioum daemon on any Linux server using our 1-click installation script. The script automatically preserves your configuration across updates.

Installation Order: You MUST install the Foreign Node first to generate the Authentication Token required by the Iran Node.

### Step 1: Deploy Foreign Node (Egress)
Run the following command on your foreign VPS:

    bash <(curl -s https://raw.githubusercontent.com/hedioum/Hedioum-Pool-Tunnel/main/install.sh)

Follow the interactive wizard. Copy the generated Auth Token.

### Step 2: Deploy Iran Node (Hub)
Run the same command on your Iran VPS:

    bash <(curl -s https://raw.githubusercontent.com/hedioum/Hedioum-Pool-Tunnel/main/install.sh)

Select "Iran Node" and add your Foreign Node using the IP and Auth Token from Step 1.

## ⚙️ Management Dashboard

To manage servers, view live connection status, or read system logs, run the interactive dashboard from your terminal at any time:

    hedioum-tunnel

Options include:
- View active connection pools and live bandwidth usage.
- Add/Remove foreign egress nodes dynamically.
- View real-time daemon logs.
- Reset configuration.

## 🛠 Building from Source

If you wish to compile the static binary manually:

    git clone https://github.com/hedioum/Hedioum-Pool-Tunnel.git
    cd Hedioum-Pool-Tunnel
    make build-linux

## ☕ Support & Donate

If you found this project helpful for maintaining a free and open internet, and you want to support further development, consider buying the team a coffee!

USDT (Tether) Donation Addresses:
- TRC20 (Tron): TRhwZFoHRZ9oux4emFXTj63aib9nuC2J2J
- BEP20 (BSC): 0x051e31cb70076854C0b62F816d5a89D3def4A22E
- ERC20 (Ethereum): 0x051e31cb70076854C0b62F816d5a89D3def4A22E
- TON (The Open Network): UQCqq0wYNDVhq9AXAZ5vOQ2ZgMmP6O0UTgvU1YhNeIpkUp1s

Thank you for your support!
