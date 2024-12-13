package alert

import (
    "fmt"
    "sync"
    "time"
)

type AlertLevel int

const (
    Low AlertLevel = iota
    Medium
    High
    Critical
)

type Alert struct {
    Timestamp   time.Time
    SourceIP    string
    DestinationIP string
    Protocol    string
    ThreatType  string
    Level       AlertLevel
    Description string
}

type AlertManager struct {
    alerts      []Alert
    mutexes     sync.Mutex
    maxAlerts   int
}

func (am *AlertManager) AddAlert(alert Alert) {
    am.mutexes.Lock()
    defer am.mutexes.Unlock()

    // Prevent unlimited alert growth
    if len(am.alerts) >= am.maxAlerts {
        am.alerts = am.alerts[1:]
    }
    am.alerts = append(am.alerts, alert)
}

func (am *AlertManager) GenerateReport() string {
    am.mutexes.Lock()
    defer am.mutexes.Unlock()

    report := "Threat Detection Report\n"
    report += "---------------------\n"
    for _, alert := range am.alerts {
        report += fmt.Sprintf(
            "Time: %s | Threat: %s | Source: %s -> Dest: %s | Level: %d\n",
            alert.Timestamp.Format(time.RFC3339),
            alert.ThreatType,
            alert.SourceIP,
            alert.DestinationIP,
            alert.Level,
        )
    }
    return report
}