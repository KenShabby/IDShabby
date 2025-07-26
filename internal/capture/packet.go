package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/layers"
	"github.com/google/pcap"

	"IDShabby/internal/config"
	"IDShabby/pkg/logger"
	"IDShabby/pkg/models"
)

// PacketCapture handles the capturing of network traffic
type PacketCapture struct {
	interfaceName string
	config        config.InterfaceConfig
	handle        *pcap.Handle
	logger        *logger.Logger
	stats         *models.PacketStats
	packetChannel chan *models.PacketInfo
	stopChannel   chan bool
	isRunning     bool
}

// Initialize a new instance
func NewPacketCapture(interfaceName string, config config.InterfaceConfig,
	logger *logger.Logger) *PacketCapture {
	return &PacketCapture{
		interfaceName: interfaceName,
		config:        config,
		logger:        logger,
		stats:         models.NewPacketStats(),
		packetChannel: make(chan *models.PacketInfo, 1000),
		stopChannel:   make(chan bool, 1),
		isRunning:     false,
	}
}

// Start capturing packets
func (pc *PacketCapture) Start() error {
	if pc.isRunning {
		return fmt.Errorf("Packet capture is already running on %s", pc.interfaceName)
	}

	timeout, err := time.ParseDuration(pc.config.Timeout)
	if err != nil {
		timeout = time.second // default value
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(
		pc.interfaceName,
		int32(pc.config.BufferSize),
		pc.config.Promiscuous,
		timeout,
	)
	if err != nil {
		return fmt.Errorf("Failed to open interface %s: %w", pc.interfaceName, err)
	}

	pc.handle = handle
	pc.isRunning = true

	pc.logger.InterfaceStarted(pc.interfaceName)

	// Start packet goroutine
	go pc.captureLoop()

	return nil
}

// Stop capturing packets
func (pc *PacketCapture) Stop() {
	if !pc.isRunning {
		return
	}

	pc.stopChannel <- true
	pc.isRunning = false

	if pc.handle != nil {
		pc.handle.close()
	}

	pc.logger.WithField("interface", pc.interfaceName).Info("Packet capture stopped")
}

// Getter for packet capture stats
func (pc *PacketCapture) GetStats() *models.PacketStats {
	return pc.stats
}

// Getter for running status
func (pc *PacketCapture) IsRunning () bool {
	return pc.isRunning
}

// This is the main packet capturing loop
func (pc *PacketCapture) captureLoop() {
	defer close(pc.packetChannel)

	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	packetCount := int64(0)

	for {
		select {
		case <- pc.stopChannel:
			return

		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			packetCount++

			// Parse into our custom struct
			packetInfo := pc.parsePacket(packet)
			if packetInfo != nil {

				pc.stats.Update(packetInfo)

				// Send to processing channel
				select {
				case pc.packetChannel <- packetInfo:
					// Success
				case default:
					// Channel is full, log and drop packet
					pc.logglogger.WithField("interface", pc.interfaceName).Warn(
						"Packet channel full, dropping packet")
				}

				// Log periodic stats
				if packetCount%1000 == 0 {
					pc.logger.PacketCaptured(pc.interfaceName, packpacketCount)
				}
			}
		}
	}
}

// parsePacket converts a goPacket.Packet to our custom PacketInfo structure
func (pc *PacketCapture) parsePacket(pacpacket gopacket.Packet) *models.PacketInfo  {
	info := 
	
}
