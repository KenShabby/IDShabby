package capture

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Interface manager handles network interface operations
type InterfaceManager struct {
	interfaces map[string]*InterfaceInfo
}

// Information about the individual interface
type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
	IsUp        bool     `json:"is_up"`
	IsLoopback  bool     `json:"is_loopback"`
}

// Construct a new interface manager
func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		interfaces: make(map[string]*InterfaceInfo),
	}
}

// Discover interfaces
func (im *InterfaceManager) DiscoverInterfaces() error {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("Unable to find any network interfaces: %w", err)
	}

	// Initialize interface manager
	im.interfaces = make(map[string]*InterfaceInfo)

	// Loop through devices
	for _, device := range devices {
		info := &InterfaceInfo{
			Name:        device.Name,
			Description: device.Description,
			Addresses:   make([]string, 0),
		}

		// Get addresses
		for _, addr := range device.Addresses {
			if addr.IP != nil {
				info.Addresses = append(info.Addresses, addr.IP.String())
			}
		}

		// Make sure interface is up and not a loopback device
		if netInterface, err := net.InterfaceByName(device.Name); err == nil {
			info.IsUp = netInterface.Flags&net.FlagUp != 0
			info.IsLoopback = netInterface.Flags&net.FlagLoopback != 0
		}

		im.interfaces[device.Name] = info

	}
	return nil

}

// GetInterface returns information about a specific interface
func (im *InterfaceManager) GetInterface(name string) (*InterfaceInfo, error) {
	info, exists := im.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("interface %s is not found.", name)
	}
	return info, nil

}

// List all discovered interfaces
func (im *InterfaceManager) ListInterfaces() map[string]*InterfaceInfo {
	return im.interfaces
}

// Check to see if an interface is valid to listen to
func (im *InterfaceManager) ValidateInterface(name string) error {
	info, err := im.GetInterface(name)
	if err != nil {
		return err
	}

	if !info.IsUp {
		return fmt.Errorf("Interface %s is not up.", name)
	}

	if info.IsLoopback {
		return fmt.Errorf("Interface %s is a loopback device.", name)
	}

	return nil
}

// Return interfaces that are suitable for packet capture
func (im *InterfaceManager) GetSuitableInterfaces() []string {
	var suitable []string

	for name, info := range im.interfaces {
		if info.IsUp && !info.IsLoopback && len(info.Addresses) > 0 {
			suitable = append(suitable, name)
		}
	}

	return suitable
}
