package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"NIDS/internal/analysis"
	"NIDS/internal/capture"
	"NIDS/internal/detection"

	"github.com/google/gopacket"
)

func main() {
	capturer := &capture.PacketCapture{}

	start := time.Now()

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

	// fmt.Printf("\n----------------------\n")
	fmt.Printf("Enter the number of packets to capture : ")
	reader := bufio.NewReader(os.Stdin)
	noOfPackets, _ := reader.ReadString('\n')
	n, _ := strconv.Atoi(noOfPackets[:len(noOfPackets)-1])

	writePcap := true
	fmt.Printf("Enter the filename to save the captured packets or type Skip : ")
	pcapFile , _ := reader.ReadString('\n')
	pcapFile = pcapFile[:len(pcapFile)-1]
	if pcapFile == "Skip" {
		writePcap = false
	}
	fmt.Printf("Starting packet capture on interface: %s\n", capturer.Interface)
	fmt.Printf("Starting packet capture on %v packets\n", n)

	handle, err := capturer.StartCapture()
	if err != nil {
		log.Fatalf("Error starting packet capture: %v", err)
	}
	defer handle.Close()

	packetChan := make(chan gopacket.Packet, 100)
	td := detection.NewThreatDetector()
	packetCounter := map[string]int{}
	threatCounter := map[string]int{}
	detectedThreats := []detection.ThreatEvent{}

	go func() {
		capturer.CapturePackets(handle, n, packetChan)
	}()

	go func() {
		err := capturer.SaveToPCAP(pcapFile, packetChan, handle.LinkType())
		if err != nil {
			log.Fatalf("Error saving packets to PCAP file: %v", err)
		}
	}()

	packetCount := 0
	for packet := range packetChan {
		packetParsed := *analysis.ParsePacket(packet)
		classification := analysis.ClassifyTraffic(&packetParsed)
		if writePcap {
			// 
		}
		packetCounter[classification]++
		threats := td.DetectThreats(&packetParsed)
		
		for _, threat := range threats {
			detectedThreats = append(detectedThreats, threat)
			threatID := threat.RuleName
			threatCounter[threatID]++
		}

		packetCount++
		if packetCount >= n {
			break
		}
	}

	fmt.Println("Packet analysis completed in", time.Since(start))
	fmt.Println("Threats Counter : ")
	for k , v := range threatCounter {
		fmt.Printf("%v -> %v threats\n",k,v)
	}
}