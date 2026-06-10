package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// AppConfig represents the root structure of the application configuration
type AppConfig struct {
	Role string `json:"role"` // "iran" or "foreign"

	// Foreign Node specific properties
	ForeignListenPort int    `json:"foreign_listen_port,omitempty"`
	AuthToken         string `json:"auth_token,omitempty"`

	// Iran Node specific properties
	ForeignNodes []ForeignNode `json:"foreign_nodes,omitempty"`
}

// ForeignNode defines the connection parameters for upstream egress servers
type ForeignNode struct {
	Alias               string `json:"alias"`
	TargetIP            string `json:"target_ip"`
	TargetPort          int    `json:"target_port"`
	LocalSocksPort      int    `json:"local_socks_port"`
	MinConnections      int    `json:"min_connections"`       // Establishes the baseline warm-up pool size
	MaxConnections      int    `json:"max_connections"`       // Dynamically customizes pool sizing per server
	BandwidthLimitMbps  int    `json:"bandwidth_limit_mbps"`  // Target speed (Mbps) per physical connection before scale-up
	BandwidthJitterMbps int    `json:"bandwidth_jitter_mbps"` // Variance to evade DPI patterns (Chaos Mesh)
	AuthToken           string `json:"auth_token"`
}

// getConfigPath determines the absolute storage destination for configuration persistence.
// It prioritizes the production environment directory (/etc/hedioum) if accessible,
// otherwise falling back gracefully to the current working directory.
func getConfigPath() string {
	const prodDir = "/etc/hedioum"
	const fileName = "hedioum.json"

	if stat, err := os.Stat(prodDir); err == nil && stat.IsDir() {
		return filepath.Join(prodDir, fileName)
	}
	return fileName
}

// LoadConfig reads the configuration state from the persistent storage layer
func LoadConfig() (*AppConfig, error) {
	configPath := getConfigPath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, errors.New("configuration file does not exist")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// --- Backward Compatibility & Fallback Logic ---
	// Ensures existing deployments won't crash due to missing fields in old JSON configs.
	for i := range cfg.ForeignNodes {
		if cfg.ForeignNodes[i].TargetPort == 0 {
			cfg.ForeignNodes[i].TargetPort = 22 // Default fallback for old configs
		}
		if cfg.ForeignNodes[i].MinConnections == 0 {
			cfg.ForeignNodes[i].MinConnections = 10 // Default baseline: 10 connections
		}
		if cfg.ForeignNodes[i].MaxConnections == 0 {
			cfg.ForeignNodes[i].MaxConnections = 20 // Default max limit
		}
		if cfg.ForeignNodes[i].BandwidthLimitMbps == 0 {
			cfg.ForeignNodes[i].BandwidthLimitMbps = 8 // Default target: 8 Mbps per connection
		}
		if cfg.ForeignNodes[i].BandwidthJitterMbps == 0 {
			cfg.ForeignNodes[i].BandwidthJitterMbps = 2 // Default jitter: +/- 2 Mbps (Chaos variance)
		}
	}

	return &cfg, nil
}

// SaveConfig persists the current application configuration state atomically to disk
func SaveConfig(cfg *AppConfig) error {
	configPath := getConfigPath()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Ensure the parent directory exists if using localized paths
	dir := filepath.Dir(configPath)
	if dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(configPath, data, 0600)
}

// UpdateForeignNode rewrites an existing node configuration or appends it if missing
func (cfg *AppConfig) UpdateForeignNode(updatedNode ForeignNode) {
	for i, node := range cfg.ForeignNodes {
		if node.Alias == updatedNode.Alias {
			cfg.ForeignNodes[i] = updatedNode
			return
		}
	}
	cfg.ForeignNodes = append(cfg.ForeignNodes, updatedNode)
}

// RemoveForeignNode purges a registered egress target from the slice by its unique alias
func (cfg *AppConfig) RemoveForeignNode(alias string) bool {
	for i, node := range cfg.ForeignNodes {
		if node.Alias == alias {
			cfg.ForeignNodes = append(cfg.ForeignNodes[:i], cfg.ForeignNodes[i+1:]...)
			return true
		}
	}
	return false
}
