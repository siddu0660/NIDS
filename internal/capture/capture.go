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

func (pc *PacketCapture) CapturePackets() ([]gopacket.Packet, error) {
    handle, err := pcap.OpenLive(pc.Interface, 1600, true, pcap.BlockForever)
    if err != nil {
        return nil , fmt.Errorf("error opening device %s: %v", pc.Interface, err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := make([]gopacket.Packet, 0, 10)
    for packet := range packetSource.Packets() {
        packets = append(packets, packet)
        if(len(packets) >= 10) {
            break
        }
    }

    return packets, nil
}