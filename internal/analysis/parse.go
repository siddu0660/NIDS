package analysis

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketData struct {
	SourceIP net.IP
	SourcePort layers.TCPPort
	
	DestinationIP net.IP
	DestinationPort layers.TCPPort

	Protocol string

	Size int
}

func ParsePacket(packet gopacket.Packet) *PacketData {
	packetData := &PacketData{}

	// IP Layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		// Get IP address and size of the payload
		packetData.SourceIP = ipv4.SrcIP
		packetData.DestinationIP = ipv4.DstIP
		packetData.Size = len(ipv4.Payload)

		switch ipv4.Protocol{
			case layers.IPProtocolTCP:
            packetData.Protocol = "TCP"
        case layers.IPProtocolUDP:
            packetData.Protocol = "UDP"
        case layers.IPProtocolICMPv4:
            packetData.Protocol = "ICMPv4"
		case layers.IPProtocolICMPv6:
			packetData.Protocol = "ICMPv6"
        default:
            packetData.Protocol = "Unknown IPv4"
		}
	}

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		// Get IP address and size of the payload
		packetData.SourceIP = ipv6.SrcIP
		packetData.DestinationIP = ipv6.DstIP
		packetData.Size = len(ipv6.Payload)

		switch ipv6.NextHeader{
		case layers.IPProtocolTCP:
            packetData.Protocol = "TCP"
        case layers.IPProtocolUDP:
            packetData.Protocol = "UDP"
        case layers.IPProtocolICMPv4:
            packetData.Protocol = "ICMPv4"
		case layers.IPProtocolICMPv6:
			packetData.Protocol = "ICMPv6"
        default:
            packetData.Protocol = "Unknown IPv4"
		}
	}

	//TCP layer
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        packetData.SourcePort = tcp.SrcPort
        packetData.DestinationPort = tcp.DstPort
    }

    // UDP layer
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        packetData.SourcePort = layers.TCPPort(udp.SrcPort)
        packetData.DestinationPort = layers.TCPPort(udp.DstPort)
    }

	return packetData
}

func ClassifyTraffic(info *PacketData) string {
    switch {
    case info.Protocol == "TCP" && (info.DestinationPort == 80 || info.DestinationPort == 443):
        return "Web Traffic"
    case info.Protocol == "UDP" && info.DestinationPort == 53:
        return "DNS Traffic"
    case info.Protocol == "ICMPv4" || info.Protocol == "ICMPv6":
        return "Network Diagnostic"
    default:
        return "Unknown Traffic"
    }
}