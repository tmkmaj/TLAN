package storage

import "slices"

// Store methods return owned snapshots: callers must never receive mutable
// pointers or slices belonging to the state protected by Store.mu.
func cloneDevice(device Device) Device {
	if device.Forwarding != nil {
		forwarding := *device.Forwarding
		device.Forwarding = &forwarding
	}
	return device
}

func cloneCandidates(record CandidateRecord) CandidateRecord {
	record.Candidates = slices.Clone(record.Candidates)
	return record
}

func cloneReport(report DiagnosticReport) DiagnosticReport {
	report.Checks = slices.Clone(report.Checks)
	return report
}
