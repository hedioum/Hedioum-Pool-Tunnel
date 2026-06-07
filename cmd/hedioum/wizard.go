package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/sysutil"
)

func handleReset() {
	if err := os.Remove("/etc/hedioum/hedioum.json"); err != nil && !os.IsNotExist(err) {
		os.Remove("hedioum.json") // Fallback to local directory
	}
	color.Yellow("[-] Configuration purged. Resetting daemon state...\n")
	exec.Command("systemctl", "stop", "hedioum.service").Run()
}

func runSetupWizard() *config.AppConfig {
	var role string
	prompt := &survey.Select{
		Message: "Define the network role of this server instance:",
		Options: []string{"Foreign Egress Node (Target)", "Iran Hub Node (Ingress)"},
	}
	survey.AskOne(prompt, &role)

	cfg := &config.AppConfig{}

	if role == "Foreign Egress Node (Target)" {
		cfg.Role = "foreign"
		setupForeignNode(cfg)
	} else {
		cfg.Role = "iran"
		setupIranNode(cfg, true)
	}

	if err := config.SaveConfig(cfg); err != nil {
		color.Red("[x] Fatal: Failed to persist state: %v", err)
		os.Exit(1)
	}
	color.Green("\n[✓] State provisioned successfully.")
	return cfg
}

func setupForeignNode(cfg *config.AppConfig) {
	color.HiBlue("\n--- Foreign Egress Provisioning ---")
	detectedIP, _ := sysutil.GetPublicIPv4()

	var ip string
	survey.AskOne(&survey.Input{
		Message: "Confirm Server Public IPv4:",
		Default: detectedIP,
	}, &ip, survey.WithValidator(survey.Required))

	changeSSH := false
	survey.AskOne(&survey.Confirm{
		Message: "Move OpenSSH daemon to port 2022 to free Port 22 for DPI Decoy?",
		Default: true,
	}, &changeSSH)

	if changeSSH {
		if err := sysutil.ChangeSSHPort("2022"); err != nil {
			color.Red("[x] OpenSSH port relocation failed: %v", err)
		} else {
			color.Green("[✓] OpenSSH shifted to 2022. Decoy port available.")
		}
	}

	cfg.ForeignListenPort = 22
	cfg.AuthToken = sysutil.GenerateSecureToken()

	color.HiWhite("\n[INFO] Provisioning Summary:")
	fmt.Printf(" - Listen Port: %d\n", cfg.ForeignListenPort)
	fmt.Printf(" - Auth Token:  %s\n", color.HiYellowString(cfg.AuthToken))
	color.HiRed("   (CRITICAL: Retain this token for Iran Hub configuration)\n")
}

func setupIranNode(cfg *config.AppConfig, isFirstTime bool) {
	color.HiBlue("\n--- Egress Target Registration ---")

	node := config.ForeignNode{}

	questions := []*survey.Question{
		{
			Name:     "alias",
			Prompt:   &survey.Input{Message: "Server Alias (e.g., DE-Frankfurt-01):"},
			Validate: survey.Required,
		},
		{
			Name:     "targetip",
			Prompt:   &survey.Input{Message: "Foreign Egress IPv4 Address:"},
			Validate: survey.Required,
		},
		{
			Name:   "localsocksport",
			Prompt: &survey.Input{Message: "Local SOCKS5 Bind Port (for X-UI Outbound mapping):", Default: "40001"},
		},
		{
			Name:   "maxconnections",
			Prompt: &survey.Input{Message: "Max Physical Connections in Pool (Scale limit):", Default: "20"},
		},
		{
			Name:   "bandwidthlimit",
			Prompt: &survey.Input{Message: "Target Bandwidth Limit per Connection (Mbps):", Default: "8"},
		},
		{
			Name:   "bandwidthjitter",
			Prompt: &survey.Input{Message: "Bandwidth Jitter/Variance for DPI Evasion (Mbps):", Default: "2"},
		},
		{
			Name:     "authtoken",
			Prompt:   &survey.Input{Message: "Authentication Token (from egress server):"},
			Validate: survey.Required,
		},
	}

	answers := struct {
		Alias           string
		TargetIP        string
		LocalSocksPort  string
		MaxConnections  string
		BandwidthLimit  string
		BandwidthJitter string
		AuthToken       string
	}{}

	if err := survey.Ask(questions, &answers); err != nil {
		return
	}

	node.Alias = answers.Alias
	node.TargetIP = answers.TargetIP
	node.AuthToken = answers.AuthToken

	node.LocalSocksPort, _ = strconv.Atoi(answers.LocalSocksPort)
	node.MaxConnections, _ = strconv.Atoi(answers.MaxConnections)
	node.BandwidthLimitMbps, _ = strconv.Atoi(answers.BandwidthLimit)
	node.BandwidthJitterMbps, _ = strconv.Atoi(answers.BandwidthJitter)

	cfg.UpdateForeignNode(node)
}
