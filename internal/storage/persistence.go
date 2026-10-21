package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	normalizeState(&s.data)
	s.committed, _ = json.Marshal(s.data)
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(contents, &s.data); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	normalizeState(&s.data)
	s.committed, _ = json.Marshal(s.data)
	return s, nil
}

func (s *Store) persistLocked() (err error) {
	// Failed writes must not commit the mutation only in RAM.
	defer func() {
		if err != nil {
			var previous State
			if json.Unmarshal(s.committed, &previous) == nil {
				s.data = previous
				normalizeState(&s.data)
			}
		}
	}()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	contents, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, contents, 0o600); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.committed = append([]byte(nil), contents...)
	return nil
}

func normalizeState(state *State) {
	if state.MemberCredentials == nil {
		state.MemberCredentials = make(map[string]MemberCredential)
	}
	if state.Networks == nil {
		state.Networks = make(map[string]Network)
	}
	if state.Devices == nil {
		state.Devices = make(map[string]RegisteredDevice)
	}
	if state.Candidates == nil {
		state.Candidates = make(map[string]CandidateRecord)
	}
	if state.Diagnostics == nil {
		state.Diagnostics = make(map[string][]DiagnosticReport)
	}
	for id, n := range state.Networks {
		if n.Devices == nil {
			n.Devices = make(map[string]Device)
			state.Networks[id] = n
		}
	}
}
