package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

)

func main () {

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Open device for capture
	handle, err := pcap.OpenLive(devices[0].Name, 1600, true, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Simple packet processing for now
	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range(packets.Packets()) {
		fmt.Println(packet)
	}
}

