package sysutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

// GetPublicIPv4 safely resolves the server's public IPv4 address, forcing v4 transport
func GetPublicIPv4() (string, error) {
	// Force IPv4 dialer to prevent IPv6 leakage
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		DualStack: false,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

// ChangeSSHPort edits sshd_config safely, disables ssh.socket if present, updates UFW, and restarts the service
func ChangeSSHPort(newPort string) error {
	const sshdConfigPath = "/etc/ssh/sshd_config"
	backupPath := fmt.Sprintf("%s.bak.%d", sshdConfigPath, time.Now().Unix())

	// 1. Read existing config
	content, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	// 2. Create backup
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// 3. Regex replacement for Port directive
	configStr := string(content)
	re := regexp.MustCompile(`(?m)^#?Port\s+\d+`)
	if re.MatchString(configStr) {
		configStr = re.ReplaceAllString(configStr, "Port "+newPort)
	} else {
		// If no port directive exists, append it
		configStr += fmt.Sprintf("\nPort %s\n", newPort)
	}

	// 4. Write new config
	if err := os.WriteFile(sshdConfigPath, []byte(configStr), 0644); err != nil {
		return fmt.Errorf("failed to write new sshd_config: %w", err)
	}

	// 5. Handle systemd ssh.socket overriding port 22 in modern Ubuntu systems
	_ = exec.Command("systemctl", "stop", "ssh.socket").Run()
	_ = exec.Command("systemctl", "disable", "ssh.socket").Run()

	// 6. Handle Firewall (UFW) dynamically so the user doesn't get locked out
	if isUFWActive() {
		color.Yellow("[*] UFW Firewall is active. Opening new SSH port %s/tcp...", newPort)
		if err := exec.Command("ufw", "allow", fmt.Sprintf("%s/tcp", newPort)).Run(); err != nil {
			color.Red("[!] Warning: Failed to add UFW rule automatically. Please run 'ufw allow %s/tcp' manually.", newPort)
		} else {
			color.Green("[✓] UFW rule added successfully.")
		}
	}

	// 7. Restart SSH service (handles both 'ssh' in Ubuntu and 'sshd' in RHEL)
	cmd := exec.Command("systemctl", "restart", "ssh")
	if err := cmd.Run(); err != nil {
		// Fallback for CentOS/AlmaLinux
		exec.Command("systemctl", "restart", "sshd").Run()
	}

	// Give the SSH daemon a second to bind
	time.Sleep(1 * time.Second)

	return nil
}

// isUFWActive checks if the Uncomplicated Firewall is running
func isUFWActive() bool {
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

// GenerateSecureToken creates a 32-character random hex string for authentication
func GenerateSecureToken() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback-secure-token-12345"
	}
	return hex.EncodeToString(bytes)
}
