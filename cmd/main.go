package main

import (
	"fmt"
	"log"

	"NIDS/internal/analysis"
	"NIDS/internal/capture"
	"NIDS/internal/detection"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
    capturer := capture.PacketCapture{}

    interfaces, err := capturer.ListInterfaces()
    if err != nil {
        log.Fatalf("Failed to list interfaces: %v", err)
    }

    for _, iface := range interfaces {
        if iface != "lo" && iface != "localhost" {
            capturer.Interface = iface
            break
        }
    }

    if capturer.Interface == "" {
        log.Fatal("No suitable network interface found")
    }

    fmt.Printf("Starting packet capture on interface: %s\n", capturer.Interface)

    handle, err := pcap.OpenLive(capturer.Interface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Error opening device: %v", err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    for packet := range packetSource.Packets() {
        packetInfo := analysis.ParsePacket(packet)
        trafficType := analysis.ClassifyTraffic(packetInfo)
        threats := detection.DetectThreats(packetInfo)

        if len(threats) > 0 {
            fmt.Printf("THREAT DETECTED: %v\n", threats)
        }

        fmt.Printf("Packet: %s -> %s | Type: %s | Size: %d bytes\n", 
            packetInfo.SourceIP, 
            packetInfo.DestinationIP, 
            trafficType,
            packetInfo.Size,
        )
    }
}