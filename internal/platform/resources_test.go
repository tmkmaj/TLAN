package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func makeOwnedRecord(t *testing.T, instanceID string, resourceType ResourceType, name, prefix, resourceID, parentID string) ResourceRecord {
	t.Helper()
	record, err := NewResourceRecord(instanceID, resourceType, name, prefix, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	record.ResourceID = resourceID
	record.ParentID = parentID
	return record
}

func TestFileLedgerPersistsExactRecordsAndPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "mesh-resources.json")
	ledger, err := NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	record := makeOwnedRecord(t, "instance-a", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	records := reloaded.Records()
	if len(records) != 1 || records[0].InstanceID != record.InstanceID || records[0].Owner != record.Owner {
		t.Fatalf("reloaded records = %#v", records)
	}
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("ledger directory mode = %o, want owner-only", dirInfo.Mode().Perm())
		}
		fileInfo, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("ledger file mode = %o, want owner-only", fileInfo.Mode().Perm())
		}
	}
}

func TestFileLedgerRejectsCorruptFileWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "mesh-resources.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const corrupt = "{not-json"
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileLedger(path); err == nil {
		t.Fatal("corrupt ledger was accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != corrupt {
		t.Fatal("corrupt ledger was overwritten")
	}
}

func TestResourceRecordRejectsWildcardName(t *testing.T) {
	if _, err := NewResourceRecord("instance", ResourcePlainTransport, "LAN*", "", ""); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("wildcard record error = %v, want ErrInvalidResource", err)
	}
}

func TestRecoverUsesExactOwnedRecord(t *testing.T) {
	ledger := NewMemoryLedger()
	record := makeOwnedRecord(t, "old-instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	called := 0
	status := ledger.Recover("new-instance", func(got ResourceRecord) error {
		called++
		if got.Key() != record.Key() {
			t.Fatalf("cleaner got %#v, want %#v", got.Key(), record.Key())
		}
		return nil
	})
	if called != 1 || status.Recovered != 1 || status.Failed != 0 || status.Unproven != 0 {
		t.Fatalf("recovery status = %#v, calls=%d", status, called)
	}
	if remaining := ledger.Records(); len(remaining) != 0 {
		t.Fatalf("remaining records = %#v", remaining)
	}
}

func TestRecoverRejectsDifferentOwnerWithoutCallingCleaner(t *testing.T) {
	ledger := NewMemoryLedgerWithOwner("current-user")
	record := makeOwnedRecord(t, "old-instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	record.Owner = "another-user"
	ledger.ledgerState.records = []ResourceRecord{record}
	called := 0
	status := ledger.Recover("new-instance", func(ResourceRecord) error {
		called++
		return nil
	})
	if called != 0 || status.Unproven != 1 || status.Failed != 0 {
		t.Fatalf("recovery status = %#v, calls=%d", status, called)
	}
	remaining := ledger.Records()
	if len(remaining) != 1 || remaining[0].CleanupState != CleanupUnproven {
		t.Fatalf("remaining = %#v", remaining)
	}
}

func TestRecoverRetainsFailureForIdempotentRetry(t *testing.T) {
	ledger := NewMemoryLedger()
	record := makeOwnedRecord(t, "old-instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("cleanup unavailable")
	first := ledger.Recover("new-instance", func(ResourceRecord) error { return sentinel })
	if first.Failed != 1 || first.Recovered != 0 || len(ledger.Records()) != 1 {
		t.Fatalf("first recovery = %#v, records=%#v", first, ledger.Records())
	}
	remaining := ledger.Records()[0]
	if remaining.CleanupState != CleanupFailed || remaining.LastError == "" {
		t.Fatalf("failed record = %#v", remaining)
	}
	second := ledger.Recover("new-instance", func(ResourceRecord) error { return nil })
	if second.Recovered != 1 || len(ledger.Records()) != 0 {
		t.Fatalf("retry recovery = %#v, records=%#v", second, ledger.Records())
	}
}

func TestRecoverDoesNotDeleteWhenPendingStateCannotPersist(t *testing.T) {
	ledger := NewMemoryLedger()
	record := makeOwnedRecord(t, "old-instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	ledger.SetPersistenceError(errors.New("disk full"))
	called := 0
	status := ledger.Recover("new-instance", func(ResourceRecord) error {
		called++
		return nil
	})
	if called != 0 || status.Failed != 1 || len(ledger.Records()) != 1 {
		t.Fatalf("recovery = %#v, calls=%d, records=%#v", status, called, ledger.Records())
	}
}

func TestTrackedCleanupRetainsRecordOnFailure(t *testing.T) {
	ledger := NewMemoryLedger()
	record := makeOwnedRecord(t, "instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("cleanup failed")
	if err := TrackedCleanup(ledger, record, func(ResourceRecord) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("cleanup error = %v", err)
	}
	records := ledger.Records()
	if len(records) != 1 || records[0].CleanupState != CleanupFailed || records[0].LastError == "" {
		t.Fatalf("record after failure = %#v", records)
	}
	if err := TrackedCleanup(ledger, record, func(ResourceRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(ledger.Records()) != 0 {
		t.Fatal("successful retry left a ledger record")
	}
}

func TestIPTunnelCloseRetainsTrackedCleanupFailure(t *testing.T) {
	ledger := NewMemoryLedger()
	record := makeOwnedRecord(t, "instance", ResourcePlainTransport, "plain-a", "10.44.0.0/24", "", "")
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("close cleanup failed")
	tunnel := &IPTunnel{
		ledger:    ledger,
		resources: []ResourceRecord{record},
		cleanupBefore: func() error {
			return trackedCleanup(ledger, record, func(ResourceRecord) error { return sentinel })
		},
	}
	if err := tunnel.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close error = %v", err)
	}
	records := ledger.Records()
	if len(records) != 1 || records[0].CleanupState != CleanupFailed || records[0].LastError == "" {
		t.Fatalf("records after close failure = %#v", records)
	}
}
