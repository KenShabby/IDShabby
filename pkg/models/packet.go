// Packet data structures

package models

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// This struct will hold out packet info
type PacketInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	Interface   string    `json:"interface"`
	Length      int       `json:"length"`
	Protocol    string    `json:"protocol"`
	SourceIP    net.IP    `json:"source_ip"`
	DestIP      net.IP    `json:"dest_ip"`
	SourcePort  int16     `json:"source_port,omitempty"`
	DestPort    int16     `json:"dest_port,omitempty"`
	Flags       []string  `json:"flags,omitempty"`
	PayloadSize int       `json:"payload_size"`
	RawData     []byte    `json:"-"`
}

type ConnectionKey struct {
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"source_ip"`
	DestIP     string `json:"dest_ip"`
	SourcePort int16  `json:"source_port"`
	DestPort   int16  `json:"dest_port"`
}

// Console output of the connection key
func (ck ConnectionKey) String() string {
	if ck.SourcePort > 0 && ck.DestPort > 0 {
		return fmt.Sprintf("%s:%s:%d->%s:%d", ck.Protocol, ck.SourceIP,
			ck.SourcePort, ck.DestIP, ck.DestPort)
	}
	return fmt.Sprintf("%s:%s->%s", ck.Protocol, ck.SourceIP, ck.DestIP)
}

// Keep stats on our packets
type PacketStats struct {
	TotalPackets   int64            `json:"total_packets"`
	PacketsByProto map[string]int64 `json:"packets_by_protocol"`
	BytesTotal     int64            `json:"bytes_total"`
	StartTime      time.Time        `json:"start_time"`
	LastPacketTime time.Time        `json:"last_packet_time"`
}

// Do a constructor thingy
func NewPacketStats() *PacketStats {
	return &PacketStats{
		PacketsByProto: make(map[string]int64),
		StartTime:      time.Now(),
	}
}

// Update stats with a new packet
func (ps *PacketStats) Update(packetInfo *PacketInfo) {
	ps.TotalPackets++
	ps.PacketsByProto[packetInfo.Protocol]++
	ps.BytesTotal += int64(packetInfo.Length)
	ps.LastPacketTime = packetInfo.Timestamp
}
