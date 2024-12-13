package detection

import (
	"NIDS/internal/analysis"
)

type ThreatRule struct {
    Name        string
    Description string
    Condition   func(*analysis.PacketData) bool
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
    },
    {
        Name:        "Vulnerable HTTP Port",
        Description: "HTTP traffic on a non-standard port",
        Condition: func(info *analysis.PacketData) bool {
            return info.Protocol == "TCP" && 
					info.DestinationPort != 80 && 
					info.DestinationPort != 443
        },
    },
}

func DetectThreats(PacketData *analysis.PacketData) []string {
    threats := []string{}

    for _, rule := range DefaultThreatRules {
        if rule.Condition(PacketData) {
            threats = append(threats, rule.Name)
        }
    }

    return threats
}