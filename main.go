package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketStats struct {
	TotalPackets  int
	TCPPackets    int
	UDPPackets    int
	ICMPPackets   int
	BytesReceived int64
}

func main() {
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

	snapshot_len := int32(1600)
	promiscuousMode := true
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuousMode, pcap.BlockForever)
	if err != nil {
		fmt.Println("Could not open the device for capture")
	}
	defer handle.Close()

	fmt.Printf("Listening on interface: %s...\n", device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		packetLogger(packet)
	}
}
