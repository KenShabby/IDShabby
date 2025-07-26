package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Interfaces []InterfaceConfig `json:"interfaces"`
	Detection  DetectionConfig   `json:"detection"`
	Alerting   AlertingConfig    `json:"alerting"`
	Logging    LoggingConfig     `json:"logging"`
}

type InterfaceConfig struct {
	Name        string `json:"name"`
	Promiscuous bool   `json:"promiscuous"`
	Timeout     string `json:"timeout"`
	BufferSize  int    `json:"buffer_size"`
}

type DetectionConfig struct {
	PortScan       PortScanConfig       `json:"port_scan"`
	BruteForce     BruteForceConfig     `json:"brute_force"`
	TrafficAnomaly TrafficAnomalyConfig `json:"traffic_anomaly"`
}

type PortScanConfig struct {
	Enabled    bool   `json:"enabled"`
	Threshold  int    `json:"threshold"`
	TimeWindow string `json:"time_window"`
	Severity   string `json:"severity"`
}

type BruteForceConfig struct {
	Enabled        bool   `json:"enabled"`
	FailedAttempts int    `json:"failed_attempts"`
	TimeWindow     string `json:"time_window"`
	Severity       string `json:"severity"`
}

type TrafficAnomalyConfig struct {
	Enabled                   bool   `json:"enabled"`
	BytesPerSecondThreshold   int64  `json:"bytes_per_second_threshold"`
	PacketsPerSecondThreshold int64  `json:"packets_per_second_threshold"`
	TimeWindow                string `json:"time_window"`
}

type AlertingConfig struct {
	LogFile            string `json:"log_file"`
	ConsoleOutput      bool   `json:"console_output"`
	PrettyPrint        bool   `json:"pretty_print"`
	DedupWindow        string `json:"dedup_window"`
	MaxAlertsPerMinute int    `json:"max_alerts_per_minute"`
}

type LoggingConfig struct {
	Level       string `json:"level"`
	Format      string `json:"format"`
	File        string `json:"file"`
	Console     bool   `json:"console"`
	PrettyPrint bool   `json:"pretty_print"`
}

// LoadConfig loads configuration from JSON file
func LoadConfig(configPath string) (*Config, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %w", err)
	}

	// Validate and set defaults
	if err := config.setDefaults(); err != nil {
		return nil, fmt.Errorf("failed to set config defaults: %w", err)
	}

	return &config, nil
}

// setDefaults sets default values for missing configuration
func (c *Config) setDefaults() error {
	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.File == "" {
		c.Logging.File = "logs/ids.json"
	}

	// Alerting defaults
	if c.Alerting.LogFile == "" {
		c.Alerting.LogFile = "logs/alerts.json"
	}
	if c.Alerting.DedupWindow == "" {
		c.Alerting.DedupWindow = "300s"
	}
	if c.Alerting.MaxAlertsPerMinute == 0 {
		c.Alerting.MaxAlertsPerMinute = 100
	}

	// Interface defaults
	for i := range c.Interfaces {
		if c.Interfaces[i].Timeout == "" {
			c.Interfaces[i].Timeout = "1s"
		}
		if c.Interfaces[i].BufferSize == 0 {
			c.Interfaces[i].BufferSize = 1024
		}
	}

	return nil
}

// SaveConfig saves current configuration to JSON file
func (c *Config) SaveConfig(configPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
