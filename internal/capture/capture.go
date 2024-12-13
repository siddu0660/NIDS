package capture

import (
	"NIDS/internal/analysis"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketCapture struct {
	Interface string
}

func (pc *PacketCapture) ListInterfaces() ([]string, error) {
    // List devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        return nil, err
    }
    // Get all interfaces
    interfaces := []string{}
    for _, device := range devices {
        interfaces = append(interfaces, device.Name)
    }
    
    return interfaces, nil
}

func (pc *PacketCapture) CapturePackets() error {
    // Open device
    handle, err := pcap.OpenLive(pc.Interface, 1600, true, pcap.BlockForever)
    if err != nil {
        return fmt.Errorf("error opening device %s: %v", pc.Interface, err)
    }
    defer handle.Close()

    // Captured Packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        packetData := analysis.ParsePacket(packet)
        traffic := analysis.ClassifyTraffic(packetData)

        fmt.Printf("Packet: %s -> %s | Type: %s | Size: %d bytes\n", 
            packetData.SourceIP, 
            packetData.DestinationIP, 
            traffic,
            packetData.Size,
        )
    }

    return nil
}