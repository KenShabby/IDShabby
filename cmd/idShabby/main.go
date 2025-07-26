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

	// Handle interface listing
	if *listInterfaces {
		fmt.Println("Available network interfaces:")
		for name, info := range interfaceManager.ListInterfaces() {
			status := "DOWN"
			if info.IsUp {
				status = "UP"
			}
			fmt.Printf("  %s (%s) - %s - %v\n", name, info.Description, status, info.Addresses)
		}
		return
	}

	log.Info("Starting Intrusion Detection System")

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
