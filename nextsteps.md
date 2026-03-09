Yeah, HTTPS is just encrypted garbage without the keys. You'll see the TLS handshake and then... nothing useful. Unless you're willing to go full corporate IT overlord and MITM your own traffic (which requires installing a custom CA cert on all your devices and feels dirty), HTTPS payloads are opaque.

## HTTP & Interesting Cleartext Protocols

Here's what you CAN inspect on your LAN:

**HTTP (Port 80)**
```go
func inspectHTTP(payload []byte) {
    payloadStr := string(payload)
    
    // Request parsing
    if strings.HasPrefix(payloadStr, "GET") || 
       strings.HasPrefix(payloadStr, "POST") ||
       strings.HasPrefix(payloadStr, "PUT") {
        lines := strings.Split(payloadStr, "\r\n")
        fmt.Printf("HTTP Request: %s\n", lines[0])
        
        // Extract headers
        for _, line := range lines[1:] {
            if line == "" {
                break
            }
            if strings.HasPrefix(line, "Host:") ||
               strings.HasPrefix(line, "User-Agent:") ||
               strings.HasPrefix(line, "Cookie:") {
                fmt.Printf("  %s\n", line)
            }
        }
    }
    
    // Response parsing
    if strings.HasPrefix(payloadStr, "HTTP/1.") {
        lines := strings.Split(payloadStr, "\r\n")
        fmt.Printf("HTTP Response: %s\n", lines[0])
    }
}
```

**DNS (Port 53, UDP)**
```go
func inspectDNS(packet gopacket.Packet) {
    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer != nil {
        dns, _ := dnsLayer.(*layers.DNS)
        
        // Queries
        for _, q := range dns.Questions {
            fmt.Printf("DNS Query: %s (%s)\n", 
                string(q.Name), q.Type)
        }
        
        // Answers
        for _, a := range dns.Answers {
            fmt.Printf("DNS Answer: %s -> %s\n", 
                string(a.Name), a.IP)
        }
    }
}
```

**DHCP (Ports 67/68)**
```go
func inspectDHCP(packet gopacket.Packet) {
    dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
    if dhcpLayer != nil {
        dhcp, _ := dhcpLayer.(*layers.DHCPv4)
        fmt.Printf("DHCP: %s - Client MAC: %s\n", 
            dhcp.Operation, dhcp.ClientHWAddr)
    }
}
```

**SMB/CIFS (Port 445)** - File sharing
```go
// Look for SMB signatures
if bytes.HasPrefix(payload, []byte{0xff, 0x53, 0x4d, 0x42}) {
    fmt.Println("SMB/CIFS traffic detected")
    // Manual parsing or use a library
}
```

**FTP (Port 21)** - Still used internally sometimes
```go
if port == 21 {
    payloadStr := string(payload)
    if strings.HasPrefix(payloadStr, "USER") || 
       strings.HasPrefix(payloadStr, "PASS") {
        fmt.Printf("FTP Credentials: %s\n", payloadStr)
    }
}
```

**MDNS/Bonjour (Port 5353)** - Device discovery
```go
// Similar to DNS parsing, shows what devices are announcing themselves
```

**NetBIOS (Port 137-139)** - Windows network names
**SNMP (Port 161)** - Network device management
**Telnet (Port 23)** - If anyone's still using it (yikes)

## Multi-Protocol Inspector

```go
func deepInspect(packet gopacket.Packet) {
    // Get all layers
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    appLayer := packet.ApplicationLayer()
    
    if appLayer == nil {
        return // No payload
    }
    
    payload := appLayer.Payload()
    
    // TCP protocols
    if tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        switch tcp.DstPort {
        case 80, 8080:
            inspectHTTP(payload)
        case 21:
            inspectFTP(payload)
        case 445:
            inspectSMB(payload)
        case 23:
            fmt.Println("⚠️ Telnet detected (unencrypted!)")
        }
    }
    
    // UDP protocols
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        switch udp.DstPort {
        case 53:
            inspectDNS(packet)
        case 67, 68:
            inspectDHCP(packet)
        case 5353:
            inspectMDNS(packet)
        }
    }
    
    // Protocol-agnostic checks
    checkForSensitiveData(payload)
}

func checkForSensitiveData(payload []byte) {
    lower := strings.ToLower(string(payload))
    
    patterns := []string{
        "password", "passwd", "api_key", "apikey",
        "secret", "token", "authorization",
    }
    
    for _, pattern := range patterns {
        if strings.Contains(lower, pattern) {
            fmt.Printf("⚠️ Potential credential leak: '%s' found\n", pattern)
        }
    }
}
```

## What You'll Actually See

On a typical home LAN:
- **DNS queries** - Every website lookup (even HTTPS sites resolve via DNS)
- **DHCP** - Devices getting/renewing IP addresses  
- **MDNS** - Printers, smart devices announcing themselves
- **HTTP** - IoT devices, firmware updates, some APIs (surprisingly common)
- **NetBIOS/SMB** - Windows file sharing
- **Encrypted protocols** (HTTPS, SSH, etc.) - Metadata only (IPs, ports, timing)

The real goldmine is DNS queries. Even though HTTPS hides the content, DNS tells you exactly which domains people are accessing. You'd be surprised how much you can infer from that alone.

Want me to show you how to set up DNS query logging specifically? That's usually the most revealing cleartext protocol on modern networks.
