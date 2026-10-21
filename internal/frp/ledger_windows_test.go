//go:build windows

package frp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/winproc"
)

func TestRecoverLedgerRemovesInterruptedRuntime(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"instance-orphan", "verify-orphan"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "token.txt"), []byte("must-not-remain"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverLedger(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("orphan runtime dirs remain: %v", entries)
	}
}

func TestWriteLedgerRecordsRestrictedTokenEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "instance-token-evidence")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &launchedProcess{
		PID:          1234,
		CreationTime: 5678,
		Token: winproc.Evidence{
			SchemaVersion:         winproc.EvidenceSchemaVersion,
			TokenSource:           "created-restricted",
			UserSID:               "S-1-5-21-test",
			SessionID:             1,
			IntegrityRID:          0x2000,
			IntegrityLevel:        "Medium",
			AdminGroup:            "disabled",
			EnabledPrivilegeCount: 1,
			EnabledPrivileges:     []string{"SeChangeNotifyPrivilege"},
		},
	}
	if err := writeLedger(dir, process); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ledgerFileName))
	if err != nil {
		t.Fatal(err)
	}
	var record ledgerRecord
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.RestrictedToken == nil {
		t.Fatal("restricted token evidence is missing from ledger")
	}
	if record.RestrictedToken.IntegrityLevel != "Medium" || record.RestrictedToken.AdminGroup != "disabled" {
		t.Fatalf("unexpected token evidence: %+v", record.RestrictedToken)
	}
	if len(record.RestrictedToken.EnabledPrivileges) != 1 || record.RestrictedToken.EnabledPrivileges[0] != "SeChangeNotifyPrivilege" {
		t.Fatalf("unexpected enabled privileges: %v", record.RestrictedToken.EnabledPrivileges)
	}
}

func TestRecoverLedgerAggregatesTerminationErrors(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "instance-cleanup-failure")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &launchedProcess{PID: 1234, CreationTime: 5678}
	if err := writeLedger(dir, process); err != nil {
		t.Fatal(err)
	}
	err := recoverLedgerWith(root, func(uint32, uint64) error { return errors.New("access denied") })
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("recover ledger did not report termination failure: %v", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("runtime directory with failed termination was deleted: %v", statErr)
	}
}
