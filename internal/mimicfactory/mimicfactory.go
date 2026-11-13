// Package mimicfactory builds the client-side camouflage for an endpoint's mimic
// type. It is shared by the hub's forward dialer and the foreign's reverse dial-out,
// so whichever peer opens the TCP connection builds identical mimics.
package mimicfactory

import (
	"github.com/hedioum/Hedioum-Pool-Tunnel/config"
	"github.com/hedioum/Hedioum-Pool-Tunnel/internal/mimic"
)

// Client builds the client camouflage for an endpoint's mimic type.
func Client(ep config.Endpoint, token string) mimic.ClientMimic {
	switch ep.Mimic {
	case "tls", "smtps", "imaps", "directadmin", "https-alt", "docker", "grafana", "prometheus",
		"cpanel", "whm", "webmail":
		// Implicit TLS: every panel/registry persona shares the plain TLS mimic on its
		// own port (the disguise is server-side: the decoy shown to unauthorized probes).
		return &mimic.TLSClient{Token: token, ServerName: ep.ServerName}
	case "smtp", "imap", "postgres", "mysql":
		return &mimic.StartTLSClient{Proto: ep.Mimic, TLS: &mimic.TLSClient{Token: token, ServerName: ep.ServerName}}
	default: // "ssh"
		return &mimic.SSHClient{Token: token}
	}
}
