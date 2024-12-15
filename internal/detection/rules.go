package detection

import (
	"NIDS/internal/analysis"
	"log"
	"net"
	"sync"
	"time"
)

type ThreatRule struct {
    Name        string
    Description string
    Condition   func(*analysis.PacketData) bool
    Severity    int
}

type ThreatDetector struct {
	mu                sync.RWMutex
	rules             []ThreatRule
	threatHistory     map[string][]ThreatEvent
	connectionTracker *ConnectionTracker
}

type ThreatEvent struct {
    RuleName      string
    SourceIP      net.IP
    Description   string
    Timestamp     time.Time
    PacketDetails *analysis.PacketData
    Severity      int
}

func NewThreatDetector() *ThreatDetector {
    detector := &ThreatDetector{
        rules:             DefaultThreatRules,
        threatHistory:     make(map[string][]ThreatEvent),
        connectionTracker: NewConnectionTracker(),
    }
    return detector
}

type ConnectionTracker struct {
    mu                sync.RWMutex
    connectionCounts  map[string]int
    connectionTimes   map[string][]time.Time
    blockedIPs        map[string]time.Time
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connectionCounts:  make(map[string]int),
		connectionTimes:   make(map[string][]time.Time),
		blockedIPs:        make(map[string]time.Time),
	}
}

func (ct *ConnectionTracker) TrackConnection(ip string) bool {
    ct.mu.Lock()
    defer ct.mu.Unlock()

    if blockedUntil, exists := ct.blockedIPs[ip]; exists {
        if time.Now().Before(blockedUntil) {
            return false
        }
        delete(ct.blockedIPs, ip)
    }

    ct.connectionCounts[ip]++
    ct.connectionTimes[ip] = append(ct.connectionTimes[ip], time.Now())
    
    ct.pruneOldConnections(ip)

    if ct.connectionCounts[ip] > 100 {
        ct.blockedIPs[ip] = time.Now().Add(time.Minute)
        log.Printf("Blocked IP %s due to excessive connections", ip)
        return false
    }
    return true
}

func (ct *ConnectionTracker) pruneOldConnections(ip string) {
	cutoff := time.Now().Add(-1 * time.Minute)
	times := ct.connectionTimes[ip]
	
	var newTimes []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			newTimes = append(newTimes, t)
		}
	}
	
	ct.connectionTimes[ip] = newTimes
	ct.connectionCounts[ip] = len(newTimes)
}

func contains(flags []string, flag string) bool {
    for _, f := range flags {
        if f == flag {
            return true
        }
    }
    return false
}

func isInSameSubnet(ip1, ip2 net.IP) bool {
    ip1to4 := ( ip1.To4() != nil )
    ip2to4 := ( ip2.To4() != nil )
    
    return ip1[0] == ip2[0] && ip1to4 && ip2to4
}

var DefaultThreatRules = []ThreatRule{
    {
        Name:        "Highly Port Scan",
        Description: "Various attempts across multiple ports",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && 
					info.DestinationPort > 1000 && 
					info.DestinationPort < 1100
        },
        Severity: 4,
    },
    {
        Name:        "Vulnerable HTTP Port",
        Description: "HTTP traffic on a non-standard port",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && 
					info.DestinationPort != 80 && 
					info.DestinationPort != 443
        },
        Severity: 5,
    },
    {
        Name:        "Port Scanning",
        Description: "Suspicious activity detected across multiple destination ports.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && info.RequestRate > 100
        },
        Severity: 5,
    },
    {
        Name:        "ARP Spoofing",
        Description: "Mismatch in ARP source IP and MAC address.",
        Condition: func(info *analysis.PacketData) bool {
            return info.ARPOperation == "request" && info.ARPSourceMAC != info.MACSource
        },
        Severity: 5,
    },
    {
        Name:        "Unusual Packet Size",
        Description: "Packet size exceeds normal limits.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Size > 1500
        },
        Severity: 4,
    },
    {
        Name:        "SYN Flood",
        Description: "High number of SYN packets without completing handshake.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && contains(info.TCPFlags, "SYN") && !contains(info.TCPFlags, "ACK") && info.RequestRate > 200
        },
        Severity: 5,
    },
    {
        Name:        "ACK Flood",
        Description: "High number of ACK packets, possibly indicating flood attack.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && contains(info.TCPFlags, "ACK") && info.RequestRate > 200
        },
        Severity: 4,
    },
    {
        Name:        "Ping of Death",
        Description: "Packet size exceeds maximum ICMP size, potentially causing denial of service.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "ICMP" && info.Size > 65535
        },
        Severity: 5,
    },
    {
        Name:        "Brute Force Login",
        Description: "Excessive connection attempts to a single IP address.",
        Condition: func(info *analysis.PacketData) bool {
            return info.RequestRate > 300
        },
        Severity: 4,
    },
    {
        Name:        "Unauthorized ARP Operation",
        Description: "ARP request to a target IP that does not match expected subnet.",
        Condition: func(info *analysis.PacketData) bool {
            return info.ARPOperation == "request" && !isInSameSubnet(info.ARPSourceIP, info.ARPTargetIP)
        },
        Severity: 5,
    },
    {
        Name:        "Data Exfiltration",
        Description: "Large outbound data transfer detected.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && info.Size > 1000000
        },
        Severity: 5,
    },
    {
        Name:        "IP Fragmentation Attack",
        Description: "Unusual number of fragmented IP packets detected.",
        Condition: func(info *analysis.PacketData) bool {
            return info.Size < 576 && info.RequestRate > 100
        },
        Severity: 4,
    },
    {
        Name:        "Suspicious ARP Broadcast",
        Description: "High number of ARP broadcasts in a short period.",
        Condition: func(info *analysis.PacketData) bool {
            return info.ARPOperation == "broadcast" && info.RequestRate > 200
        },
        Severity: 4,
    },
    {
        Name:        "SSDP Spoof",
        Description: "SSDP packet with invalid source address",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "UDP" && 
					info.DestinationPort == 1900 &&
					info.SourceIP.IsGlobalUnicast() &&
					info.DestinationIP.IsGlobalUnicast()
        },
        Severity: 4,
    },
    {
        Name:        "DNS Spoof",
        Description: "DNS response with invalid source address",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "UDP" && 
					info.DestinationPort == 53 &&
					info.SourceIP.IsGlobalUnicast() &&
					info.DestinationIP.IsGlobalUnicast()
        },
        Severity: 4,
    },
}

func (td *ThreatDetector) DetectThreats(packet *analysis.PacketData) []ThreatEvent {
    var detectedThreats []ThreatEvent

    if packet == nil {
        return detectedThreats
    }

    for _, rule := range td.rules {
        if rule.Condition(packet) {
            threat := ThreatEvent{
                RuleName:       rule.Name,
                SourceIP:       packet.SourceIP,
                Description:    rule.Description,
                Timestamp:      time.Now(),
                PacketDetails:  packet,
                Severity:       rule.Severity,
            }
            
            td.recordThreat(threat)
            detectedThreats = append(detectedThreats, threat)
        }
    }

    return detectedThreats
}

func (td *ThreatDetector) recordThreat(threat ThreatEvent) {
    td.mu.Lock()
    defer td.mu.Unlock()

    td.threatHistory[threat.SourceIP.String()] = append(td.threatHistory[threat.SourceIP.String()], threat)

    // log.Printf(
    //     "THREAT DETECTED: %s from %s - %s (Severity: %d)", 
	// 	threat.RuleName, 
	// 	threat.SourceIP, 
	// 	threat.Description, 
	// 	threat.Severity,
    // )
}

func (td *ThreatDetector) GetThreatHistory(ip string) []ThreatEvent {
    td.mu.RLock()
    defer td.mu.RUnlock()

    return td.threatHistory[ip]
}