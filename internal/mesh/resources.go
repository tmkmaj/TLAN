package mesh

import (
	"errors"

	"github.com/private-radminlan/lanmesh/internal/platform"
)

type ResourceRecord = platform.ResourceRecord
type RecoveryStatus = platform.RecoveryStatus

func (e *Engine) registerTransportResources() error {
	if e.ledger == nil {
		return nil
	}
	specs := []struct {
		resourceType platform.ResourceType
		name         string
	}{
		{platform.ResourceWireGuardTransport, "wireguard-go"},
		{platform.ResourcePlainTransport, "TmkNetworkLAN-encrypted"},
	}
	for _, spec := range specs {
		record, err := platform.NewResourceRecord(e.instanceID, spec.resourceType, spec.name, e.options.Network.CIDR, "")
		if err != nil {
			return err
		}
		if err := e.ledger.Add(record); err != nil {
			return err
		}
		e.transport = append(e.transport, record)
	}
	return nil
}

func (e *Engine) closeTransportResources() error {
	if e.ledger == nil || len(e.transport) == 0 {
		return nil
	}
	var errs []error
	for _, record := range e.transport {
		// Transport records have no OS resource. Removing the record is the
		// complete cleanup; the cleaner still runs through the same ownership
		// and persistence path for consistent failure reporting.
		err := platform.TrackedCleanup(e.ledger, record, func(platform.ResourceRecord) error { return nil })
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Resources returns the records owned by this Engine instance. Stale records
// from prior instances remain visible through the ledger/recovery status.
func (e *Engine) Resources() []ResourceRecord {
	if e == nil || e.ledger == nil {
		return nil
	}
	all := e.ledger.Records()
	result := make([]ResourceRecord, 0)
	for _, record := range all {
		if record.InstanceID == e.instanceID {
			result = append(result, record)
		}
	}
	return result
}

// RecoveryStatus reports what happened while recovering resources from prior
// Engine instances. It is safe to expose to the GUI as a read-only snapshot.
func (e *Engine) RecoveryStatus() RecoveryStatus {
	if e == nil {
		return RecoveryStatus{}
	}
	status := e.recovery
	status.Issues = append([]platform.ResourceRecoveryIssue(nil), status.Issues...)
	e.mu.RLock()
	cleanupError := e.cleanupError
	e.mu.RUnlock()
	if e.ledger != nil {
		all := e.ledger.Records()
		remaining := make([]ResourceRecord, 0)
		for _, record := range all {
			if record.CleanupState == platform.CleanupFailed || record.CleanupState == platform.CleanupUnproven || record.CleanupState == platform.CleanupCleaned {
				remaining = append(remaining, record)
			}
		}
		status.Remaining = remaining
		for _, record := range all {
			if record.CleanupState != platform.CleanupFailed && record.CleanupState != platform.CleanupUnproven {
				continue
			}
			issue := platform.ResourceRecoveryIssue{
				Resource: record,
				Error:    record.LastError,
				Unproven: record.CleanupState == platform.CleanupUnproven,
			}
			duplicate := false
			for _, existing := range status.Issues {
				if existing.Resource.Key() == issue.Resource.Key() && existing.Error == issue.Error {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			status.Issues = append(status.Issues, issue)
			if issue.Unproven {
				status.Unproven++
			} else {
				status.Failed++
			}
		}
	}
	if cleanupError != "" {
		duplicate := false
		for _, existing := range status.Issues {
			if existing.Error == cleanupError {
				duplicate = true
				break
			}
		}
		if !duplicate {
			status.Issues = append(status.Issues, platform.ResourceRecoveryIssue{Error: cleanupError})
			status.Failed++
		}
	}
	return status
}

// InstanceID returns the unique ownership ID for this Engine instance.
func (e *Engine) InstanceID() string {
	if e == nil {
		return ""
	}
	return e.instanceID
}
