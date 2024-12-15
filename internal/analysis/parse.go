package analysis

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketData struct {
	SourceIP net.IP
	SourcePort layers.TCPPort
	ARPSourceIP      net.IP
	ARPSourceMAC     string
	
	DestinationIP net.IP
	DestinationPort layers.TCPPort
	ARPTargetIP      net.IP
	ARPTargetMAC     string

	MACSource string
	MACDestination string

	Size int

	Protocol string
	ARPOperation     string
	TCPFlags        []string
	RequestRate     int
}

var (
	packetCounter int
	mutex sync.Mutex
	lastFetchedTime time.Time
)
func ParsePacket(packet gopacket.Packet) *PacketData {
	packetData := &PacketData{}

	mutex.Lock()
	defer mutex.Unlock()

	if lastFetchedTime.IsZero() {
		lastFetchedTime = time.Now()
	} else {
		duration := time.Since(lastFetchedTime)
		if duration >= time.Second {
			packetData.RequestRate = packetCounter
			packetCounter = 0
			lastFetchedTime = time.Now()
		}
	}

	packetCounter++

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		packetData.MACSource = eth.SrcMAC.String()
		packetData.MACDestination = eth.DstMAC.String()
	}

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

		flags := []string{}
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}

		packetData.TCPFlags = flags
    }

    // UDP layer
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        packetData.SourcePort = layers.TCPPort(udp.SrcPort)
        packetData.DestinationPort = layers.TCPPort(udp.DstPort)
    }

	// ARP Layer
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)

		packetData.Protocol = "ARP"

		packetData.ARPSourceIP = net.IP(arp.SourceProtAddress)
		packetData.ARPSourceMAC = net.HardwareAddr(arp.SourceHwAddress).String()
		packetData.ARPTargetIP = net.IP(arp.DstProtAddress)
		packetData.ARPTargetMAC = net.HardwareAddr(arp.DstHwAddress).String()

		if arp.Operation == layers.ARPRequest {
			packetData.ARPOperation = "Request"
		} else if arp.Operation == layers.ARPReply {
			packetData.ARPOperation = "Reply"
		}
	}

	// ICMP Layer
	icmp4Layer := packet.Layer(layers.LayerTypeICMPv4)
	if icmp4Layer != nil {
		packetData.Protocol = "ICMPv4"
	}

	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmp6Layer != nil {
		packetData.Protocol = "ICMPv6"
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
	case info.Protocol == "ARP" && info.ARPOperation == "Request":
		return "ARP Request"
	case info.Protocol == "ARP" && info.ARPOperation == "Request":
		return "ARP Reply"
		}	
	return "Unknown Traffic"
}

func ReportPacket(packet PacketData) {
	fmt.Println(packet.SourceIP,packet.SourcePort,packet.DestinationIP,packet.DestinationPort,packet.Protocol)
}