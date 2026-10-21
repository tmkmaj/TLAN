package network

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
)

type DiagnosticCheck struct {
	Name    string
	Status  CheckStatus
	Detail  string
	Checked time.Time
}

type DiagnosticReport struct {
	DeviceID  core.DeviceID
	NetworkID core.NetworkID
	Checks    []DiagnosticCheck
	Created   time.Time
}

func NewDiagnosticReport(device core.DeviceID, network core.NetworkID) (*DiagnosticReport, error) {
	if err := device.Validate(); err != nil {
		return nil, err
	}
	if err := network.Validate(); err != nil {
		return nil, err
	}
	return &DiagnosticReport{DeviceID: device, NetworkID: network, Created: time.Now().UTC()}, nil
}

func (r *DiagnosticReport) Add(name string, status CheckStatus, detail string) error {
	if r == nil {
		return errors.New("nil diagnostic report")
	}
	if name == "" {
		return errors.New("diagnostic check name is required")
	}
	if status != CheckPass && status != CheckWarn && status != CheckFail {
		return errors.New("invalid diagnostic status")
	}
	r.Checks = append(r.Checks, DiagnosticCheck{Name: name, Status: status, Detail: detail, Checked: time.Now().UTC()})
	return nil
}

func (r DiagnosticReport) SortChecks() {
	sort.SliceStable(r.Checks, func(i, j int) bool { return r.Checks[i].Name < r.Checks[j].Name })
}

func (r DiagnosticReport) Healthy() bool {
	for _, check := range r.Checks {
		if check.Status == CheckFail {
			return false
		}
	}
	return true
}

// AddSTUNProbe executes a bounded STUN binding probe and records its result in
// the report. The probe is deliberately an explicit diagnostic action: callers
// choose the server and can enforce their own allow-list before invoking it.
func (r *DiagnosticReport) AddSTUNProbe(ctx context.Context, client STUNClient, server string) error {
	if r == nil {
		return errors.New("nil diagnostic report")
	}
	if client == nil {
		return errors.New("nil STUN client")
	}
	if strings.TrimSpace(server) == "" {
		return errors.New("STUN server address is required")
	}
	result, err := client.Probe(ctx, server)
	if err != nil {
		return r.Add("stun_binding", CheckFail, fmt.Sprintf("server %s: %v", server, err))
	}
	if !result.SupportsUDP || strings.TrimSpace(result.MappedAddress) == "" {
		return r.Add("stun_binding", CheckFail, fmt.Sprintf("server %s returned no usable mapped address", server))
	}
	detail := fmt.Sprintf("server %s mapped address %s; NAT=%s", server, result.MappedAddress, result.NAT)
	status := CheckPass
	if result.NAT == NATUnknown || result.NAT == NATSymmetric {
		status = CheckWarn
	}
	return r.Add("stun_binding", status, detail)
}
