package main

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
)

// Advanced settings menus. They gather the options that most users never need - such as
// sharing a port like 443 with nginx / HAProxy - behind one entry, each with its ON/OFF
// state in the label. Nothing here changes unless the operator picks it.

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

// foreignProxyOn reports whether any front-proxy setting is active on a foreign.
func foreignProxyOn(cfg *config.AppConfig) bool {
	return len(cfg.AdvertisePorts) > 0 || cfg.ListenBind != "" || cfg.ProxyProtocol
}

// runForeignAdvancedMenu is the foreign's "Advanced Settings" entry.
func runForeignAdvancedMenu(cfg *config.AppConfig) {
	for {
		optProxy := fmt.Sprintf("Front proxy (nginx / HAProxy shares a port such as 443)   [%s]", onOff(foreignProxyOn(cfg)))
		optSource := "Share an SNI with a real service: proxy config routed by the hub's IP"
		optToken := "Pairing token for the hub (with the proxy's public port)"
		var choice string
		if err := survey.AskOne(&survey.Select{
			Message: "Advanced settings (everything here is off unless you turn it on):",
			Options: []string{optProxy, optSource, optToken, "Back"},
		}, &choice); err != nil || choice == "Back" {
			return
		}
		switch choice {
		case optProxy:
			runForeignFrontProxyMenu(cfg)
		case optSource:
			showForeignConfigBySource(cfg)
		case optToken:
			cmdPairingToken(nil)
		}
	}
}

// showForeignConfigBySource prints the proxy configuration that sends the hub's address
// to the tunnel whatever SNI it presents, so the tunnel can share an SNI with a real
// service. It only prints.
func showForeignConfigBySource(cfg *config.AppConfig) {
	sp, err := foreignFrontSpec(cfg)
	if err != nil {
		color.Red("[x] %v", err)
		return
	}
	var spec string
	_ = survey.AskOne(&survey.Input{Message: "IP address(es) of the Iran hub, comma separated:"}, &spec)
	ips, err := parseSourceIPs(strings.TrimSpace(spec))
	if err != nil || len(ips) == 0 {
		color.Red("[x] Enter at least one exact IP address.")
		return
	}
	sp.Sources = ips
	var kind string
	_ = survey.AskOne(&survey.Select{Message: "Which proxy?", Options: []string{"nginx", "haproxy"}}, &kind)
	fmt.Println()
	if kind == "haproxy" {
		fmt.Println(haproxyFor(sp, 443))
	} else {
		fmt.Println(nginxFor(sp, 443))
	}
}
