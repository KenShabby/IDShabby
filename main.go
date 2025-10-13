package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	// Gather available devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Could not find any network devices.")
	}

	// List devices
	for _, device := range devices {
		fmt.Println(device)
	}

	device := devices[0].Name

	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("Could not open the device for capture")
	}

	defer handle.Close()

	fmt.Printf("Listening on interface: %s...\n", device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
