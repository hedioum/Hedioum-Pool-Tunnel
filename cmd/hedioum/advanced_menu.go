package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
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
		optToken := "Pairing token for the hub (with the proxy's public port)"
		var choice string
		if err := survey.AskOne(&survey.Select{
			Message: "Advanced settings (everything here is off unless you turn it on):",
			Options: []string{optProxy, optToken, "Back"},
		}, &choice); err != nil || choice == "Back" {
			return
		}
		switch choice {
		case optProxy:
			runForeignFrontProxyMenu(cfg)
		case optToken:
			cmdPairingToken(nil)
		}
	}
}
