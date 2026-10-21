package network

import (
	"context"
	"errors"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

type fakeSTUNClient struct {
	result STUNResult
	err    error
}

func (f fakeSTUNClient) Probe(context.Context, string) (STUNResult, error) {
	return f.result, f.err
}

func TestDiagnosticReportAddSTUNProbe(t *testing.T) {
	report, err := NewDiagnosticReport(core.DeviceID("device-1"), core.NetworkID("network-1"))
	if err != nil {
		t.Fatal(err)
	}
	err = report.AddSTUNProbe(context.Background(), fakeSTUNClient{
		result: STUNResult{MappedAddress: "203.0.113.1:5000", SupportsUDP: true, NAT: NATOpen},
	}, "stun.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 1 || report.Checks[0].Status != CheckPass {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
}

func TestDiagnosticReportAddSTUNProbeFailure(t *testing.T) {
	report, err := NewDiagnosticReport(core.DeviceID("device-1"), core.NetworkID("network-1"))
	if err != nil {
		t.Fatal(err)
	}
	err = report.AddSTUNProbe(context.Background(), fakeSTUNClient{err: errors.New("timeout")}, "stun.example:3478")
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() || len(report.Checks) != 1 || report.Checks[0].Status != CheckFail {
		t.Fatalf("unexpected failure check: %+v", report.Checks)
	}
}
