#!/bin/bash

# ==========================================================
# Hedioum Dynamic Pool Tunnel - 1-Click Installer & Updater
# ==========================================================

if [ "$EUID" -ne 0 ]; then
  echo "[x] CRITICAL: Please run the installer as root (e.g., sudo bash install.sh)"
  exit 1
fi

echo "=================================================="
echo "  Deploying Hedioum Stealth Mesh Daemon..."
echo "=================================================="

mkdir -p /etc/hedioum
mkdir -p /usr/local/bin

# --- Stop service and unlink binary to prevent 'Text file busy' error ---
if systemctl is-active --quiet hedioum.service; then
    echo "[*] Stopping existing daemon to apply update..."
    systemctl stop hedioum.service > /dev/null 2>&1
fi
rm -f /usr/local/bin/hedioum-tunnel

# --- Architecture Detection ---
OS_ARCH=$(uname -m)
TARGET_ASSET="hedioum-tunnel"

if [ "$OS_ARCH" = "aarch64" ] || [ "$OS_ARCH" = "arm64" ]; then
    TARGET_ASSET="hedioum-tunnel-arm64"
    echo "[*] Detected ARM64 architecture."
else
    echo "[*] Detected AMD64/x86_64 architecture."
fi

# --- Dynamic Release Downloader (GitHub API) ---
echo "[*] Fetching the latest release from GitHub..."

# Match exactly target asset using double quotes to avoid partial matches
LATEST_URL=$(curl -s https://api.github.com/repos/hedioum/Hedioum-Pool-Tunnel/releases/latest | grep "browser_download_url" | grep "$TARGET_ASSET\"" | cut -d '"' -f 4)

# Fallback URLs in case GitHub API is rate-limited or blocked
if [ -z "$LATEST_URL" ]; then
    echo "[-] GitHub API rate-limited or blocked. Falling back to static release link..."
    FALLBACK_VERSION="v0.5.0"
    LATEST_URL="https://github.com/hedioum/Hedioum-Pool-Tunnel/releases/download/${FALLBACK_VERSION}/${TARGET_ASSET}"
fi

URL_PROXY="https://ghp.ci/$LATEST_URL"

if curl -f -L -s -o /usr/local/bin/hedioum-tunnel "$LATEST_URL"; then
    echo "[✓] Binary downloaded successfully (Direct Release)."
elif curl -f -L -s -o /usr/local/bin/hedioum-tunnel "$URL_PROXY"; then
    echo "[✓] Binary downloaded successfully (Proxy Fallback for Iran Hub)."
else
    echo "[x] ERROR: Failed to download the binary. Network is severely restricted."
    echo "    Try running the installer again later, or use a VPN."
    exit 1
fi

chmod +x /usr/local/bin/hedioum-tunnel

# --- Configuring Systemd background service ---
echo "[*] Configuring Systemd background service..."
cat << 'EOF' > /etc/systemd/system/hedioum.service
[Unit]
Description=Hedioum Dynamic Pool Tunnel Daemon
# Order after ssh so the decoy sshd banner can be mirrored on boot.
After=network.target ssh.service sshd.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/hedioum
# Open the listen port on the host firewall BEFORE the sandboxed daemon starts.
# The '+' runs this step with full privileges (outside the sandbox below), which
# the firewall edit needs; the long-running daemon itself stays locked down.
ExecStartPre=+/usr/local/bin/hedioum-tunnel --open-firewall
ExecStart=/usr/local/bin/hedioum-tunnel
Restart=always
RestartSec=5
LimitNOFILE=1048576

# --- Sandbox hardening ---
# The daemon only needs to bind a low port, dial the network + the local decoy,
# and read /etc/hedioum. It never modifies system files at runtime (config edits
# happen from the interactive dashboard). Drop every capability except binding a
# privileged port, and lock down the filesystem/kernel surface.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/hedioum
ProtectHome=true
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hedioum.service > /dev/null 2>&1

echo "=================================================="
if [ ! -f "/etc/hedioum/hedioum.json" ]; then
    echo -e "[!] Fresh installation detected. Launching Initial Setup Wizard..."
    sleep 2
    cd /etc/hedioum && hedioum-tunnel
    echo -e "\n[✓] Setup complete! Hedioum Daemon is now running in the background."
else
    echo "[✓] Existing configuration found. Applying seamless update..."
    systemctl restart hedioum.service
    echo "[✓] Hedioum Daemon updated and restarted gracefully."
fi

echo "=================================================="
echo " [Ops] Management Dashboard Command:"
echo " Simply type 'hedioum-tunnel' anywhere in your terminal."
echo "=================================================="