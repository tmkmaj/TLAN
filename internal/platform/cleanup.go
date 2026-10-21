package platform

import (
	"errors"
	"fmt"
)

// CleanupResource performs the platform-safe cleanup path using the real
// system runner. It never guesses at a process name or a similar network.
func CleanupResource(record ResourceRecord) error {
	return CleanupResourceWithRunner(record, SystemRunner{})
}

// CleanupResourceWithRunner is the injectable cleanup entry point used by
// recovery tests. Ownership is checked before any runner call is made.
func CleanupResourceWithRunner(record ResourceRecord, runner Runner) error {
	owner, err := CurrentOwner()
	if err != nil {
		return fmt.Errorf("%w: identify current user: %v", ErrResourceNotOwned, err)
	}
	if record.Owner != owner {
		return fmt.Errorf("%w: record owner %q does not match current user", ErrResourceNotOwned, record.Owner)
	}
	if err := validateResourceRecord(record); err != nil {
		return fmt.Errorf("%w: %v", ErrResourceNotOwned, err)
	}
	if runner == nil {
		runner = SystemRunner{}
	}
	return cleanupResource(record, runner)
}

// TrackedCleanup is the exported form used by Mesh for logical transport
// records and by tests that need the same pending/failed persistence contract.
func TrackedCleanup(ledger ResourceLedger, record ResourceRecord, cleaner Cleaner) error {
	return trackedCleanup(ledger, record, cleaner)
}

// trackedCleanup persists a pending state before touching the system. If the
// ledger cannot be updated, the resource is left untouched so a future retry
// still has an exact ownership record.
func trackedCleanup(ledger ResourceLedger, record ResourceRecord, cleaner Cleaner) error {
	if cleaner == nil {
		cleaner = CleanupResource
	}
	if ledger != nil {
		if err := ledger.UpdateState(record.Key(), CleanupPending, nil); err != nil {
			return err
		}
	}
	cleanupErr := cleaner(record)
	if ledger == nil {
		return cleanupErr
	}
	if cleanupErr == nil {
		if err := ledger.Remove(record.Key()); err != nil {
			return errors.Join(cleanupErr, err)
		}
		return nil
	}
	state := CleanupFailed
	if errors.Is(cleanupErr, ErrResourceNotOwned) || errors.Is(cleanupErr, ErrResourceUnsupported) {
		state = CleanupUnproven
	}
	if err := ledger.UpdateState(record.Key(), state, cleanupErr); err != nil {
		return errors.Join(cleanupErr, err)
	}
	return cleanupErr
}
