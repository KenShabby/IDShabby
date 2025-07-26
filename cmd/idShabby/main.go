package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"IDShabby/internal/capture"
	"IDShabby/internal/config"
	"IDShabby/pkg/logger"
)

func main() {
	// Command line flags
	configPath := flag.String("config", "configs/config.json", "Path to configuration file")
	listInterfaces := flag.Bool("list-interfaces", false, "List available network interfaces")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.NewLogger(logger.Config{
		Level:       cfg.Logging.Level,
		Format:      cfg.Logging.Format,
		File:        cfg.Logging.File,
		Console:     cfg.Logging.Console,
		PrettyPrint: cfg.Logging.PrettyPrint,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	log.ConfigLoaded(*configPath)

	// Initialize interface manager
	interfaceManager := capture.NewInterfaceManager()
	if err := interfaceManager.DiscoverInterfaces(); err != nil {
		log.WithError(err).Fatal("Failed to discover network interfaces")
	}

	// Handle config generation
	generateConfig := flag.Bool("generate-config", false, "Generate default configuration file")
	if *generateConfig {
		if err := generateDefaultConfig(*configPath, interfaceManager); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default configuration generated at: %s\n", *configPath)
		fmt.Println("Please review and customize the configuration before running the IDS.")
		return
	}

	log.Info("Starting Intrusion Detection System")
	// Handle interface listing
	if *listInterfaces {
		fmt.Println("Available network interfaces:")
		suitable := interfaceManager.GetSuitableInterfaces()
		for name, info := range interfaceManager.ListInterfaces() {
			status := "DOWN"
			if info.IsUp {
				status = "UP"
			}
			recommended := ""
			for _, s := range suitable {
				if s == name {
					recommended = " (RECOMMENDED)"
					break
				}
			}
			fmt.Printf("  %s (%s) - %s - %v%s\n", name, info.Description, status, info.Addresses, recommended)
		}
		return
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start packet capture on configured interfaces
	var captures []*capture.PacketCapture

	for _, interfaceConfig := range cfg.Interfaces {
		// Validate interface
		if err := interfaceManager.ValidateInterface(interfaceConfig.Name); err != nil {
			log.WithError(err).Warnf("Skipping interface %s", interfaceConfig.Name)
			continue
		}

		// Create and start packet capture
		packetCapture := capture.NewPacketCapture(interfaceConfig.Name, interfaceConfig, log)
		if err := packetCapture.Start(); err != nil {
			log.WithError(err).Errorf("Failed to start capture on %s", interfaceConfig.Name)
			continue
		}

		captures = append(captures, packetCapture)

		// Start packet processing goroutine
		go processPackets(packetCapture, log)
	}

	if len(captures) == 0 {
		log.Fatal("No interfaces available for packet capture")
	}

	// Print statistics every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			for _, capture := range captures {
				stats := capture.GetStats()
				log.WithFields(map[string]interface{}{
					"interface":     capture.GetInterfaceName(), // You'll need to expose this
					"total_packets": stats.TotalPackets,
					"bytes_total":   stats.BytesTotal,
					"protocols":     stats.PacketsByProto,
				}).Info("Packet capture statistics")
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutting down Intrusion Detection System")

	// Stop all captures
	for _, capture := range captures {
		capture.Stop()
	}

	ticker.Stop()
}

// loadOrCreateConfig loads existing config or creates a default one
func loadOrCreateConfig(configPath string, interfaceManager *capture.InterfaceManager) (*config.Config, error) {
	// Try to load existing config
	if cfg, err := config.LoadConfig(configPath); err == nil {
		// Validate that configured interfaces still exist
		if err := validateConfigInterfaces(cfg, interfaceManager); err != nil {
			fmt.Printf("Warning: Configuration validation failed: %v\n", err)
			fmt.Println("Consider regenerating config with --generate-config")
		}
		return cfg, nil
	}

	// Config doesn't exist, offer to create it
	fmt.Printf("Configuration file not found: %s\n", configPath)
	fmt.Print("Would you like to generate a default configuration? (y/N): ")

	var response string
	fmt.Scanln(&response)

	if response == "y" || response == "Y" {
		if err := generateDefaultConfig(configPath, interfaceManager); err != nil {
			return nil, fmt.Errorf("failed to generate default config: %w", err)
		}
		fmt.Printf("Default configuration created at: %s\n", configPath)
		fmt.Println("Please review the configuration and run the program again.")
		os.Exit(0)
	}

	return nil, fmt.Errorf("configuration required to proceed")
}

// generateDefaultConfig creates a sensible default configuration
func generateDefaultConfig(configPath string, interfaceManager *capture.InterfaceManager) error {
	// Get suitable interfaces
	suitableInterfaces := interfaceManager.GetSuitableInterfaces()

	// Create interface configs for suitable interfaces
	var interfaceConfigs []config.InterfaceConfig

	if len(suitableInterfaces) == 0 {
		// No suitable interfaces found, create a placeholder
		interfaceConfigs = append(interfaceConfigs, config.InterfaceConfig{
			Name:        "YOUR_INTERFACE_HERE",
			Promiscuous: true,
			Timeout:     "1s",
			BufferSize:  1024,
		})
	} else {
		// For simplicity, just use the first one
		interfaceConfigs = append(interfaceConfigs, config.InterfaceConfig{
			Name:        suitableInterfaces[0],
			Promiscuous: true,
			Timeout:     "1s",
			BufferSize:  1024,
		})
	}

	// Create default configuration
	defaultConfig := &config.Config{
		Interfaces: interfaceConfigs,
		Detection: config.DetectionConfig{
			PortScan: config.PortScanConfig{
				Enabled:    true,
				Threshold:  10,
				TimeWindow: "30s",
				Severity:   "high",
			},
			BruteForce: config.BruteForceConfig{
				Enabled:        true,
				FailedAttempts: 5,
				TimeWindow:     "60s",
				Severity:       "critical",
			},
			TrafficAnomaly: config.TrafficAnomalyConfig{
				Enabled:                   true,
				BytesPerSecondThreshold:   1000000, // 1MB/s
				PacketsPerSecondThreshold: 1000,    // 1000 pps
				TimeWindow:                "10s",
			},
		},
		Alerting: config.AlertingConfig{
			LogFile:            "logs/alerts.json",
			ConsoleOutput:      true,
			PrettyPrint:        false,
			DedupWindow:        "300s", // 5 minutes
			MaxAlertsPerMinute: 100,
		},
		Logging: config.LoggingConfig{
			Level:       "info",
			Format:      "json",
			File:        "logs/ids.json",
			Console:     true,
			PrettyPrint: false,
		},
	}

	// Save the configuration
	return defaultConfig.SaveConfig(configPath)
}

// validateConfigInterfaces checks if configured interfaces are still available
func validateConfigInterfaces(cfg *config.Config, interfaceManager *capture.InterfaceManager) error {
	var unavailableInterfaces []string

	for _, ifaceConfig := range cfg.Interfaces {
		if err := interfaceManager.ValidateInterface(ifaceConfig.Name); err != nil {
			unavailableInterfaces = append(unavailableInterfaces, ifaceConfig.Name)
		}
	}

	if len(unavailableInterfaces) > 0 {
		return fmt.Errorf("configured interfaces not available: %v", unavailableInterfaces)
	}

	return nil
}

// processPackets handles packets from a capture instance
func processPackets(packetCapture *capture.PacketCapture, log *logger.Logger) {
	for packet := range packetCapture.GetPacketChannel() {
		// For now, just log interesting packets
		if packet.Protocol == "TCP" && (packet.DestPort == 22 || packet.DestPort == 80 || packet.DestPort == 443) {
			log.WithFields(map[string]interface{}{
				"protocol":     packet.Protocol,
				"source_ip":    packet.SourceIP.String(),
				"dest_ip":      packet.DestIP.String(),
				"dest_port":    packet.DestPort,
				"payload_size": packet.PayloadSize,
				"flags":        packet.Flags,
			}).Debug("Interesting packet captured")
		}
	}
}
