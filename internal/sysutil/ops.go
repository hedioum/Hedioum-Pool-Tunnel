package sysutil

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/color"
)

const (
	binaryPath = "/usr/local/bin/hedioum-tunnel"
	backupPath = "/usr/local/bin/hedioum-tunnel.bak"
	tmpPath    = "/tmp/hedioum-tunnel-new"
	repoAPI    = "https://api.github.com/repos/hedioum/Hedioum-Pool-Tunnel/releases/latest"
	proxyURL   = "https://ghp.ci/"
)

// GitHubRelease represents the structure of the GitHub API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// SelfUpdate orchestrates a safe zero-downtime update with an automatic rollback mechanism.
func SelfUpdate(currentVersion string) {
	color.Cyan("[*] Checking for updates...")

	// 1. Fetch latest release info
	resp, err := http.Get(repoAPI)
	if err != nil {
		color.Red("[x] Failed to contact GitHub API: %v", err)
		return
	}
	defer resp.Body.Close()

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		color.Red("[x] Failed to parse GitHub API response: %v", err)
		return
	}

	if release.TagName == "" || release.TagName == currentVersion {
		color.Green("[✓] You are already running the latest version (%s).", currentVersion)
		return
	}

	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == "hedioum-tunnel" {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		color.Red("[x] Could not find 'hedioum-tunnel' binary in the latest release.")
		return
	}

	color.Yellow("[*] New version found: %s. Starting safe update...", release.TagName)

	// 2. Download the new binary safely to /tmp
	if err := downloadFile(tmpPath, downloadURL); err != nil {
		color.Red("[x] Download failed: %v", err)
		return
	}

	// Integrity check (ensure file is not empty)
	stat, err := os.Stat(tmpPath)
	if err != nil || stat.Size() < 1024*1024 { // Assuming binary is at least 1MB
		color.Red("[x] Downloaded file appears corrupted or too small. Aborting update.")
		os.Remove(tmpPath)
		return
	}

	// 3. Backup current working binary
	color.Cyan("[*] Creating backup of current version...")
	if err := os.Rename(binaryPath, backupPath); err != nil {
		color.Red("[x] Failed to create backup: %v", err)
		return
	}

	// 4. Install new binary
	if err := os.Rename(tmpPath, binaryPath); err != nil {
		color.Red("[x] Failed to deploy new binary. Rolling back...")
		rollback()
		return
	}
	os.Chmod(binaryPath, 0755)

	// 5. Restart service and Verify
	color.Cyan("[*] Restarting daemon to apply version %s...", release.TagName)
	exec.Command("systemctl", "restart", "hedioum.service").Run()
	time.Sleep(2 * time.Second) // Wait for service to attempt startup

	// 6. Health Check & Rollback
	if err := exec.Command("systemctl", "is-active", "--quiet", "hedioum.service").Run(); err != nil {
		color.HiRed("[!] CRITICAL: New version crashed upon startup. Initiating auto-rollback!")
		rollback()
		return
	}

	// Cleanup backup on success
	os.Remove(backupPath)
	color.Green("\n[✓] Update successful! Hedioum Daemon is now running %s.", release.TagName)
}

// downloadFile tries the direct link, and falls back to a proxy if blocked (Anti-Censorship)
func downloadFile(filepath string, url string) error {
	// Try direct download via curl
	cmd := exec.Command("curl", "-f", "-L", "-s", "-o", filepath, url)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Fallback to proxy
	color.Yellow("[-] Direct download failed. Attempting via proxy fallback...")
	proxyLink := proxyURL + url
	cmdProxy := exec.Command("curl", "-f", "-L", "-s", "-o", filepath, proxyLink)
	return cmdProxy.Run()
}

// rollback restores the previous binary and restarts the service
func rollback() {
	if err := os.Rename(backupPath, binaryPath); err != nil {
		color.Red("[x] FATAL: Rollback failed! Manual intervention required.")
		return
	}
	exec.Command("systemctl", "restart", "hedioum.service").Run()
	color.Yellow("[-] System has been successfully rolled back to the previous version.")
}

// Uninstall safely purges all Hedioum components from the server
func Uninstall() {
	color.Yellow("[*] Stopping and disabling Hedioum service...")
	exec.Command("systemctl", "stop", "hedioum.service").Run()
	exec.Command("systemctl", "disable", "hedioum.service").Run()

	color.Yellow("[*] Removing Systemd service file...")
	os.Remove("/etc/systemd/system/hedioum.service")
	exec.Command("systemctl", "daemon-reload").Run()

	color.Yellow("[*] Removing binaries and configuration files...")
	os.RemoveAll("/etc/hedioum")
	os.Remove(binaryPath)
	os.Remove(backupPath)

	color.Green("[✓] Hedioum has been completely removed from this system.")
	os.Exit(0)
}
