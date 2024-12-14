package main

import (
	"fmt"
	"log"

	"NIDS/internal/analysis"
	"NIDS/internal/capture"
	"NIDS/internal/detection"
)

func main() {
	capturer := &capture.PacketCapture{}

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

	packets, err := capturer.CapturePackets()
	if err != nil {
		log.Fatalf("Error capturing packets: %v", err)
	}

    td := detection.NewThreatDetector()
    packetCounter := map[string]int {}
    detectedThreats := make([]detection.ThreatEvent,0)

	for _, packet := range packets {
        packetParsed := *analysis.ParsePacket(packet)
        classification := analysis.ClassifyTraffic(&packetParsed)
        packetCounter[classification] += 1

        threat := td.DetectThreats(&packetParsed)
        detectedThreats = append(detectedThreats, threat...)
	}

    // fmt.Println(detectedThreats)
    fmt.Println(packetCounter)
}
