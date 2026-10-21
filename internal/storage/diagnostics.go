package storage

import (
	"errors"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

func (s *Store) SaveDiagnostics(report DiagnosticReport) (DiagnosticReport, error) {
	if err := report.DeviceID.Validate(); err != nil {
		return DiagnosticReport{}, err
	}
	if err := report.NetworkID.Validate(); err != nil {
		return DiagnosticReport{}, err
	}
	if len(report.Checks) == 0 || len(report.Checks) > 64 {
		return DiagnosticReport{}, errors.New("between 1 and 64 diagnostic checks are required")
	}
	for _, check := range report.Checks {
		if strings.TrimSpace(check.Name) == "" || len(check.Name) > 128 {
			return DiagnosticReport{}, errors.New("diagnostic check name is required")
		}
		if check.Status != "pass" && check.Status != "warn" && check.Status != "fail" {
			return DiagnosticReport{}, errors.New("invalid diagnostic status")
		}
		if len(check.Detail) > 2048 {
			return DiagnosticReport{}, errors.New("diagnostic detail is too long")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Networks[report.NetworkID.String()]; !ok {
		return DiagnosticReport{}, ErrNotFound
	}
	if _, ok := s.data.Devices[report.DeviceID.String()]; !ok {
		return DiagnosticReport{}, ErrNotFound
	}
	if _, ok := s.data.Networks[report.NetworkID.String()].Devices[report.DeviceID.String()]; !ok {
		return DiagnosticReport{}, ErrNotFound
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	key := candidateKey(report.NetworkID, report.DeviceID)
	reports := append(s.data.Diagnostics[key], cloneReport(report))
	if len(reports) > 20 {
		reports = reports[len(reports)-20:]
	}
	s.data.Diagnostics[key] = reports
	if err := s.persistLocked(); err != nil {
		return DiagnosticReport{}, err
	}
	return report, nil
}

func (s *Store) ListDiagnostics(networkID core.NetworkID, deviceID core.DeviceID) ([]DiagnosticReport, error) {
	if err := networkID.Validate(); err != nil {
		return nil, err
	}
	if err := deviceID.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	network, networkOK := s.data.Networks[networkID.String()]
	reports, ok := s.data.Diagnostics[candidateKey(networkID, deviceID)]
	if !networkOK {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	if _, member := network.Devices[deviceID.String()]; !member {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	if !ok {
		s.mu.RUnlock()
		return []DiagnosticReport{}, nil
	}
	result := append([]DiagnosticReport(nil), reports...)
	for i := range result {
		result[i] = cloneReport(result[i])
	}
	s.mu.RUnlock()
	return result, nil
}
