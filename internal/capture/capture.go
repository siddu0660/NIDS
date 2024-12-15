package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketCapture struct {
	Interface string
}

func (pc *PacketCapture) ListInterfaces() ([]string, error) {
    devices, err := pcap.FindAllDevs()
    if err != nil {
        return nil, err
    }
    interfaces := []string{}
    for _, device := range devices {
        interfaces = append(interfaces, device.Name)
    }
    
    return interfaces, nil
}

func (pc *PacketCapture) StartCapture() (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(pc.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", pc.Interface, err)
	}
	return handle, nil
}

func (pc *PacketCapture) CapturePackets(handle *pcap.Handle, n int, packetChan chan<- gopacket.Packet) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range packetSource.Packets() {
		packetChan <- packet
		packetCount++
		if packetCount >= n {
			break
		}
	}

	close(packetChan)
}
