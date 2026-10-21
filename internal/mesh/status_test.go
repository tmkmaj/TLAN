package mesh

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDiagnosticsFitServerFields(t *testing.T) {
	longName := strings.Repeat("网", 42) + "PC"
	status := Status{Address: "10.243.0.1", LastError: strings.Repeat("故障", 600), Peers: []PeerStatus{
		{ID: "device-a", Name: longName, IP: "10.243.0.2", Path: "checking"},
		{ID: "device-b", Name: "short name", IP: "10.243.0.3", Path: "checking"},
	}}
	checks := diagnosticsForStatus(status)
	if len(checks) != 4 {
		t.Fatalf("checks = %d", len(checks))
	}
	if checks[1].Name != "peer device-a" || !strings.Contains(checks[1].Detail, longName) {
		t.Fatal("long device name was lost")
	}
	if checks[2].Name != "peer short name" {
		t.Fatal("ordinary check name changed")
	}
	for _, check := range checks {
		if len(check.Name) > 128 || len(check.Detail) > 2048 || !utf8.ValidString(check.Detail) {
			t.Fatalf("invalid diagnostic field: %s", check.Name)
		}
	}
}
