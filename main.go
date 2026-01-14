package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	SourceIP   string
	DestIP     string
	SourcePort uint16
	DestPort   uint16
	Protocol   string
	Payload    []byte

	Timestamp time.Time

	// IDS specific
	ThreatLevel int
	Anomaly     bool
}

type PacketStats struct {
	TotalPackets  int
	TCPPackets    int
	UDPPackets    int
	ICMPPackets   int
	BytesReceived int64
}

func main() {
	device := networkDeviceSelect()
	snapshot_len := int32(1600)
	promiscuousMode := true
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuousMode, pcap.BlockForever)
	if err != nil {
		fmt.Println("Could not open the device for capture")
	}
	defer handle.Close()

	fmt.Printf("Listening on interface: %s...\n", device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetStats := &PacketStats{}

	maxPackets := 100
	count := 0

	for packet := range packetSource.Packets() {
		p := extractPacketInfo(packet)
		packetLogger(p.SourceIP)
		packetLogger(p.DestIP)
		packetStats.TotalPackets++
		count++
		if count >= maxPackets {
			break
		}
	}

	printPacketStats(packetStats)
}

func extractPacketInfo(packet gopacket.Packet) *Packet {
	p := &Packet{
		Timestamp: packet.Metadata().Timestamp,
	}

	// Extract IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		p.SourceIP = ip.SrcIP.String()
		p.DestIP = ip.DstIP.String()
		p.Protocol = ip.Protocol.String()
	}

	// Extract TCP Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.SourcePort = uint16(tcp.SrcPort)
		p.DestPort = uint16(tcp.DstPort)
		p.Payload = tcp.Payload
	}
	return p
}

func networkDeviceSelect() string {
	// Gather available devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Could not find any network devices.")
	}

	// List devices
	fmt.Println("Found the following interfaces:")
	for i, device := range devices {
		fmt.Printf("%d: %s\n", i, device.Name)
	}

	// Prompt user for interface choice
	fmt.Printf("Choose an interface to monitor: ")
	var interfaceChoice int
	fmt.Scanln(&interfaceChoice)
	fmt.Printf("interfaceChoice is: %d\n", interfaceChoice)

	device := devices[int(interfaceChoice)].Name

	return device
}

func printPacketStats(ps *PacketStats) {
	fmt.Println("Packet stats:")
	fmt.Printf("Total packets received: %v\n", ps.TotalPackets)
	fmt.Printf("Total TCP packets: %v\n", ps.TCPPackets)
	fmt.Printf("Total UDP packets: %v\n", ps.UDPPackets)
	fmt.Printf("Total ICMP packets: %v\n", ps.ICMPPackets)
	fmt.Printf("Total bytes received: %v\n", ps.BytesReceived)
}
