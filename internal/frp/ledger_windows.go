//go:build windows

package frp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/internal/winproc"
)

const ledgerFileName = "ledger.json"

type ledgerRecord struct {
	SchemaVersion   int               `json:"schemaVersion"`
	InstanceID      string            `json:"instanceId"`
	OwnerSID        string            `json:"ownerSid"`
	PID             uint32            `json:"pid"`
	CreationTime    uint64            `json:"creationTime"`
	RuntimeDir      string            `json:"runtimeDir"`
	StartedAt       string            `json:"startedAt"`
	RestrictedToken *winproc.Evidence `json:"restrictedToken,omitempty"`
}

func writeLedger(dir string, process *launchedProcess) error {
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	tokenEvidence := process.Token
	record := ledgerRecord{
		SchemaVersion:   SchemaVersion,
		InstanceID:      filepath.Base(dir),
		OwnerSID:        owner,
		PID:             process.PID,
		CreationTime:    process.CreationTime,
		RuntimeDir:      dir,
		StartedAt:       time.Now().UTC().Format(time.RFC3339),
		RestrictedToken: &tokenEvidence,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(dir, ledgerFileName), append(data, '\n'))
}

func recoverLedger(root string) error {
	return recoverLedgerWith(root, terminateOwnedProcess)
}

func recoverLedgerWith(root string, terminate func(uint32, uint64) error) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan FRP runtime ledger: %w", err)
	}
	owner, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("verify FRP runtime ledger owner: %w", err)
	}
	var cleanupErrors []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "instance-") && !strings.HasPrefix(name, "verify-") {
			continue
		}
		dir := filepath.Join(root, name)
		data, readErr := os.ReadFile(filepath.Join(dir, ledgerFileName))
		if readErr != nil {
			if !errors.Is(readErr, os.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("read FRP runtime ledger %s: %w", dir, readErr))
				continue
			}
			// The runtime root is protected by the current user's DACL. A
			// directory without a ledger was created by an interrupted
			// prepare/verify step, so remove it rather than retaining a token.
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove orphan FRP runtime %s: %w", dir, removeErr))
			}
			continue
		}
		var record ledgerRecord
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || record.SchemaVersion != SchemaVersion || record.OwnerSID != owner || !safeRuntimeDir(root, record.RuntimeDir) {
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove invalid FRP runtime %s: %w", dir, removeErr))
			}
			continue
		}
		if terminate != nil {
			if terminateErr := terminate(record.PID, record.CreationTime); terminateErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("terminate stale FRP process %d: %w", record.PID, terminateErr))
				// Keep the runtime directory so the next startup can retry the
				// exact process identity instead of guessing or deleting evidence.
				continue
			}
		}
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove stale FRP runtime %s: %w", dir, removeErr))
		}
	}
	if len(cleanupErrors) > 0 {
		return errors.Join(cleanupErrors...)
	}
	return nil
}
func safeRuntimeDir(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	return true
}
