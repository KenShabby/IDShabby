package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"IDShabby/internal/config"
	"IDShabby/pkg/logger"
	"IDShabby/pkg/models"
)

// PacketCapture handles the structure of capturing network traffic
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
		timeout = time.Second // default value
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
		pc.handle.Close()
	}

	pc.logger.WithField("interface", pc.interfaceName).Info("Packet capture stopped")
}

// Getter for packet capture stats
func (pc *PacketCapture) GetStats() *models.PacketStats {
	return pc.stats
}

// GetPacketChannel returns the channel for receiving parsed packets
func (pc *PacketCapture) GetPacketChannel() <-chan *models.PacketInfo {
	return pc.packetChannel
}

// GetInterfaceName returns the interface name for this capture
func (pc *PacketCapture) GetInterfaceName() string {
	return pc.interfaceName
}

// Getter for running status
func (pc *PacketCapture) IsRunning() bool {
	return pc.isRunning
}

// This is the main packet capturing loop
func (pc *PacketCapture) captureLoop() {
	defer close(pc.packetChannel)

	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	packetCount := int64(0)

	for {
		select {
		case <-pc.stopChannel:
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
				default:
					// Channel is full, log and drop packet
					pc.logger.WithField("interface", pc.interfaceName).Warn(
						"Packet channel full, dropping packet")
				}

				// Log periodic stats
				if packetCount%1000 == 0 {
					pc.logger.PacketCaptured(pc.interfaceName, packetCount)
				}
			}
		}
	}
}

// parsePacket converts a goPacket.Packet to our custom PacketInfo structure
func (pc *PacketCapture) parsePacket(packet gopacket.Packet) *models.PacketInfo {
	info := &models.PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Interface: pc.interfaceName,
		Length:    packet.Metadata().Length,
		RawData:   packet.Data(),
	}

	// Parse IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok {
			info.SourceIP = ip.SrcIP
			info.DestIP = ip.DstIP
			info.Protocol = ip.Protocol.String()
		}
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv6); ok {
			info.SourceIP = ip.SrcIP
			info.DestIP = ip.DstIP
			info.Protocol = ip.NextHeader.String()
		}
	}

	// Parse Transport Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			info.SourcePort = int(tcp.SrcPort)
			info.DestPort = int(tcp.DstPort)
			info.Protocol = "TCP"
			info.PayloadSize = len(tcp.Payload)

			// Parse TCP flags
			info.Flags = pc.parseTCPFlags(tcp)
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			info.SourcePort = int(udp.SrcPort)
			info.DestPort = int(udp.DstPort)
			info.Protocol = "UDP"
			info.PayloadSize = len(udp.Payload)
		}
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		info.Protocol = "ICMP"
	}

	// If we couldn't determine protocol, use generic
	if info.Protocol == "" {
		info.Protocol = "Unknown"
	}

	return info
}

// Parse the TCP Flags
func (pc *PacketCapture) parseTCPFlags(tcp *layers.TCP) []string {
	var flags []string

	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}

	return flags
}
