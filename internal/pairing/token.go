// Package pairing defines the self-contained pairing token a foreign node prints and
// an operator pastes into the hub. Where the v1 token was a bare 32-hex auth secret
// that had to be paired with a hand-typed --target-ip and a matching --mimics/--persona,
// the v2 token carries everything the hub needs — the exit IP, the auth key (which is
// also the persona seed), the chosen persona, the TLS SNI, and the actual mimic->port
// map — so hub onboarding is paste-only. The v1 hex token is still accepted.
package pairing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

// Version is the current pairing-token version.
const Version = 2

// Token is a v2 pairing token payload.
type Token struct {
	Version   int            `json:"v"`
	ExitIP    string         `json:"ip"`
	AuthKey   string         `json:"auth"`              // the 32-hex auth secret (also the persona seed)
	Persona   string         `json:"persona,omitempty"` // informational: the persona the foreign wears
	SNI       string         `json:"sni,omitempty"`     // TLS SNI/CN the hub should present ("" = self-signed)
	Endpoints map[string]int `json:"eps"`               // mimic type -> public port the foreign listens on
	// Reverse marks a REVERSE-tunnel token printed by the hub: ExitIP is then the HUB's
	// address and Endpoints are the ports the hub listens on, which the foreign dials
	// out to. Absent (false) for the usual foreign-printed token, so old tokens decode
	// unchanged.
	Reverse bool `json:"rev,omitempty"`
	// MinConns / MaxConns are the pipe range the hub asks a reverse foreign to keep open
	// (the hub's own node range), so the hub configures it and the foreign needs no flag.
	// Absent in older tokens, which decode unchanged and keep the foreign's default.
	MinConns int `json:"min,omitempty"`
	MaxConns int `json:"max,omitempty"`
}

var legacyHex = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)

// IsLegacyHex reports whether s is a bare v1 auth token (32 hex chars).
func IsLegacyHex(s string) bool { return legacyHex.MatchString(s) }

// Encode renders a token as a compact base64url pairing string.
func Encode(t Token) string {
	t.Version = Version
	b, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode parses a pairing string. It returns (token, true, nil) for a valid v2 token,
// (nil, false, nil) for a bare v1 hex token (the caller falls back to the flag-driven
// flow), or (nil, false, err) for anything malformed.
func Decode(s string) (*Token, bool, error) {
	if IsLegacyHex(s) {
		return nil, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, false, fmt.Errorf("token is neither a v1 hex token nor a valid v2 pairing token")
		}
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, false, fmt.Errorf("invalid v2 pairing token: %w", err)
	}
	if t.Version != Version {
		return nil, false, fmt.Errorf("unsupported pairing token version %d (want %d)", t.Version, Version)
	}
	if err := t.validate(); err != nil {
		return nil, false, err
	}
	return &t, true, nil
}

func (t Token) validate() error {
	if !legacyHex.MatchString(t.AuthKey) {
		return fmt.Errorf("pairing token has an invalid auth key")
	}
	if t.ExitIP == "" {
		return fmt.Errorf("pairing token has no exit IP")
	}
	if len(t.Endpoints) == 0 {
		return fmt.Errorf("pairing token has no endpoints")
	}
	for ty, port := range t.Endpoints {
		if port < 1 || port > 65535 {
			return fmt.Errorf("pairing token endpoint %q has invalid port %d", ty, port)
		}
	}
	return nil
}
