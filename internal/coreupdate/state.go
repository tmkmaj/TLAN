package coreupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const stateSchemaVersion = 1

type diskState struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	TargetName    string `json:"targetName"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	InstalledAt   string `json:"installedAt"`
}

func loadState(statePath string) (diskState, []byte, bool, error) {
	info, err := os.Lstat(statePath)
	if os.IsNotExist(err) {
		return diskState{}, nil, false, nil
	}
	if err != nil {
		return diskState{}, nil, false, fmt.Errorf("coreupdate: inspect state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return diskState{}, nil, false, fmt.Errorf("%w: state file is a symbolic link", ErrSymlink)
	}
	if !info.Mode().IsRegular() {
		return diskState{}, nil, false, fmt.Errorf("%w: state file is not regular", ErrStateCorrupt)
	}
	if info.Size() > maxStateBytes {
		return diskState{}, nil, false, fmt.Errorf("%w: state file is too large", ErrStateCorrupt)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return diskState{}, nil, false, fmt.Errorf("coreupdate: read state: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return diskState{}, nil, false, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state diskState
	if err := dec.Decode(&state); err != nil {
		return diskState{}, nil, false, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return diskState{}, nil, false, fmt.Errorf("%w: trailing state JSON", ErrStateCorrupt)
		}
		return diskState{}, nil, false, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	if err := validateState(state); err != nil {
		return diskState{}, nil, false, err
	}
	return state, data, true, nil
}

func validateState(state diskState) error {
	if state.SchemaVersion != stateSchemaVersion {
		return fmt.Errorf("%w: unsupported state schema", ErrStateCorrupt)
	}
	if _, err := parseVersion(state.Version); err != nil {
		return fmt.Errorf("%w: invalid state version", ErrStateCorrupt)
	}
	if !platformPattern.MatchString(state.Platform) {
		return fmt.Errorf("%w: invalid state platform", ErrStateCorrupt)
	}
	if err := validateTargetName(state.TargetName); err != nil {
		return fmt.Errorf("%w: invalid state target", ErrStateCorrupt)
	}
	if !sha256Pattern.MatchString(state.SHA256) {
		return fmt.Errorf("%w: invalid state hash", ErrStateCorrupt)
	}
	if state.Size <= 0 {
		return fmt.Errorf("%w: invalid state size", ErrStateCorrupt)
	}
	if _, err := parseTimestamp(state.InstalledAt, "installedAt"); err != nil {
		return fmt.Errorf("%w: invalid state timestamp", ErrStateCorrupt)
	}
	return nil
}

func marshalState(state diskState) ([]byte, error) {
	if err := validateState(state); err != nil {
		return nil, err
	}
	return json.MarshalIndent(state, "", "  ")
}

func (i *Installer) writeStateBytes(root, statePath string, data []byte) error {
	f, err := os.CreateTemp(root, tempStatePrefix+"*")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := secureFile(name, 0o600); err != nil {
		return err
	}
	if err := i.atomicReplace(name, statePath); err != nil {
		return err
	}
	ok = true
	if err := syncDir(root); err != nil {
		return err
	}
	return nil
}

func (i *Installer) replaceState(root, statePath string, state diskState) error {
	data, err := marshalState(state)
	if err != nil {
		return err
	}
	return i.writeStateBytes(root, statePath, data)
}

func (i *Installer) rollbackInstall(root, targetPath, statePath, backupPath string, oldTargetExists, oldStateExists bool, oldStateBytes []byte) error {
	var errs []error
	if oldTargetExists {
		if backupPath == "" {
			errs = append(errs, errors.New("old target exists but no rollback backup was created"))
		} else if err := i.atomicReplace(backupPath, targetPath); err != nil {
			errs = append(errs, fmt.Errorf("restore old target: %w", err))
		}
	} else if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove new target: %w", err))
	}
	if oldStateExists {
		if len(oldStateBytes) == 0 {
			errs = append(errs, errors.New("old state exists but no rollback state was captured"))
		} else if err := i.writeStateBytes(root, statePath, oldStateBytes); err != nil {
			errs = append(errs, fmt.Errorf("restore old state: %w", err))
		}
	} else if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove new state: %w", err))
	}
	if err := syncDir(root); err != nil {
		errs = append(errs, fmt.Errorf("sync rollback: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if backupPath != "" {
		if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove rollback backup: %w", err)
		}
	}
	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
