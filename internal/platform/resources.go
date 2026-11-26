package platform

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ResourceType identifies a resource that can be created by the Mesh data
// plane. The type is persisted so recovery never has to infer ownership from
// a process name, a wildcard, or an address range.
type ResourceType string

const (
	ResourceWintunInterface    ResourceType = "wintun_interface"
	ResourceIPv4Address        ResourceType = "ipv4_address"
	ResourceMTU                ResourceType = "mtu"
	ResourceMetric             ResourceType = "metric"
	ResourceBroadcastRoute     ResourceType = "broadcast_route"
	ResourceMulticastRoute     ResourceType = "multicast_route"
	ResourceFirewallRule       ResourceType = "firewall_rule"
	ResourceWireGuardTransport ResourceType = "wireguard_transport"
	ResourcePlainTransport     ResourceType = "plain_transport"
)

// Aliases keep call sites readable while retaining the explicit persisted
// values above.
const (
	ResourceInterface = ResourceWintunInterface
	ResourceAddress   = ResourceIPv4Address
	ResourceRoute     = ResourceBroadcastRoute
	ResourceFirewall  = ResourceFirewallRule
)

type CleanupState string

const (
	CleanupActive   CleanupState = "active"
	CleanupPending  CleanupState = "cleanup_pending"
	CleanupFailed   CleanupState = "cleanup_failed"
	CleanupUnproven CleanupState = "unproven"
	CleanupCleaned  CleanupState = "cleaned"
)

// ResourceRecord is the durable proof of ownership for one resource. Name and
// Prefix are deliberately exact values; ResourceID/ParentID carry a system
// identity (for example an adapter GUID) when one is available.
type ResourceRecord struct {
	InstanceID   string       `json:"instance_id"`
	Type         ResourceType `json:"type"`
	Name         string       `json:"name"`
	Prefix       string       `json:"prefix,omitempty"`
	Owner        string       `json:"owner"`
	ResourceID   string       `json:"resource_id,omitempty"`
	ParentID     string       `json:"parent_id,omitempty"`
	CleanupState CleanupState `json:"cleanup_state"`
	LastError    string       `json:"last_error,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at,omitempty"`
}

// ResourceKey is the exact identity used for ledger updates. Owner and the
// system identity are part of the key, so a record for a different user or a
// different adapter can never update this record by accident.
type ResourceKey struct {
	InstanceID string
	Type       ResourceType
	Name       string
	Prefix     string
	Owner      string
	ResourceID string
	ParentID   string
}

func (r ResourceRecord) Key() ResourceKey {
	return ResourceKey{
		InstanceID: r.InstanceID,
		Type:       r.Type,
		Name:       r.Name,
		Prefix:     r.Prefix,
		Owner:      r.Owner,
		ResourceID: r.ResourceID,
		ParentID:   r.ParentID,
	}
}

type ResourceRecoveryIssue struct {
	Resource ResourceRecord `json:"resource"`
	Error    string         `json:"error"`
	Unproven bool           `json:"unproven"`
}

type RecoveryStatus struct {
	CheckedAt time.Time               `json:"checked_at"`
	Checked   int                     `json:"checked"`
	Recovered int                     `json:"recovered"`
	Failed    int                     `json:"failed"`
	Unproven  int                     `json:"unproven"`
	Issues    []ResourceRecoveryIssue `json:"issues,omitempty"`
	Remaining []ResourceRecord        `json:"remaining,omitempty"`
}

func (s RecoveryStatus) HasIssues() bool {
	return len(s.Issues) > 0 || s.Failed > 0 || s.Unproven > 0
}

type Cleaner func(ResourceRecord) error

var (
	// ErrResourceNotOwned means that the exact system identity could not be
	// proven. Recovery reports it and never attempts a deletion.
	ErrResourceNotOwned = errors.New("resource ownership cannot be proven")
	// ErrResourceUnsupported means this platform has no safe automated cleanup
	// path. It is also retained and reported rather than guessed at.
	ErrResourceUnsupported = errors.New("resource cleanup is unsupported on this platform")
	ErrInvalidResource     = errors.New("invalid resource record")
)

func (t ResourceType) Valid() bool {
	switch t {
	case ResourceWintunInterface, ResourceIPv4Address, ResourceMTU, ResourceMetric,
		ResourceBroadcastRoute, ResourceMulticastRoute, ResourceFirewallRule,
		ResourceWireGuardTransport, ResourcePlainTransport:
		return true
	default:
		return false
	}
}

func (s CleanupState) Valid() bool {
	switch s {
	case CleanupActive, CleanupPending, CleanupFailed, CleanupUnproven, CleanupCleaned:
		return true
	default:
		return false
	}
}

func NewInstanceID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate mesh instance ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

// NewResourceRecord creates an owned record. Callers must only invoke this
// after the corresponding resource was successfully created or configured.
func NewResourceRecord(instanceID string, resourceType ResourceType, name, prefix, resourceID string) (ResourceRecord, error) {
	owner, err := CurrentOwner()
	if err != nil {
		return ResourceRecord{}, fmt.Errorf("identify current user: %w", err)
	}
	now := time.Now().UTC()
	record := ResourceRecord{
		InstanceID:   strings.TrimSpace(instanceID),
		Type:         resourceType,
		Name:         name,
		Prefix:       prefix,
		Owner:        owner,
		ResourceID:   resourceID,
		CleanupState: CleanupActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := validateResourceBase(record); err != nil {
		return ResourceRecord{}, err
	}
	return record, nil
}

func validateResourceBase(record ResourceRecord) error {
	if strings.TrimSpace(record.InstanceID) == "" {
		return fmt.Errorf("%w: instance ID is empty", ErrInvalidResource)
	}
	if !record.Type.Valid() {
		return fmt.Errorf("%w: unknown type %q", ErrInvalidResource, record.Type)
	}
	if !validExactName(record.Name) {
		return fmt.Errorf("%w: invalid or wildcard resource name %q", ErrInvalidResource, record.Name)
	}
	if strings.TrimSpace(record.Owner) == "" {
		return fmt.Errorf("%w: owner is empty", ErrInvalidResource)
	}
	if record.CleanupState == "" {
		record.CleanupState = CleanupActive
	}
	if !record.CleanupState.Valid() {
		return fmt.Errorf("%w: unknown cleanup state %q", ErrInvalidResource, record.CleanupState)
	}
	return nil
}

func validateResourceRecord(record ResourceRecord) error {
	if err := validateResourceBase(record); err != nil {
		return err
	}
	switch record.Type {
	case ResourceWintunInterface:
		if _, err := netip.ParsePrefix(record.Prefix); err != nil {
			return fmt.Errorf("%w: interface prefix %q: %v", ErrInvalidResource, record.Prefix, err)
		}
		if strings.TrimSpace(record.ResourceID) == "" {
			return fmt.Errorf("%w: interface resource ID is empty", ErrInvalidResource)
		}
	case ResourceIPv4Address:
		if _, err := netip.ParsePrefix(record.Prefix); err != nil {
			return fmt.Errorf("%w: address prefix %q: %v", ErrInvalidResource, record.Prefix, err)
		}
		if strings.TrimSpace(record.ParentID) == "" {
			return fmt.Errorf("%w: address parent ID is empty", ErrInvalidResource)
		}
	case ResourceMTU:
		value, err := strconv.Atoi(record.Prefix)
		if err != nil || value < 576 || value > 1500 {
			return fmt.Errorf("%w: invalid MTU %q", ErrInvalidResource, record.Prefix)
		}
		if strings.TrimSpace(record.ParentID) == "" {
			return fmt.Errorf("%w: MTU parent ID is empty", ErrInvalidResource)
		}
	case ResourceMetric:
		value, err := strconv.Atoi(record.Prefix)
		if err != nil || value < 1 || value > 9999 {
			return fmt.Errorf("%w: invalid metric %q", ErrInvalidResource, record.Prefix)
		}
		if strings.TrimSpace(record.ParentID) == "" {
			return fmt.Errorf("%w: metric parent ID is empty", ErrInvalidResource)
		}
	case ResourceBroadcastRoute, ResourceMulticastRoute:
		if _, err := netip.ParsePrefix(record.Prefix); err != nil {
			return fmt.Errorf("%w: route prefix %q: %v", ErrInvalidResource, record.Prefix, err)
		}
		if strings.TrimSpace(record.ParentID) == "" {
			return fmt.Errorf("%w: route parent ID is empty", ErrInvalidResource)
		}
	case ResourceFirewallRule:
		if _, err := netip.ParsePrefix(record.Prefix); err != nil {
			return fmt.Errorf("%w: firewall prefix %q: %v", ErrInvalidResource, record.Prefix, err)
		}
		if strings.TrimSpace(record.ResourceID) == "" {
			return fmt.Errorf("%w: firewall resource ID is empty", ErrInvalidResource)
		}
		if strings.TrimSpace(record.ParentID) == "" {
			return fmt.Errorf("%w: firewall parent ID is empty", ErrInvalidResource)
		}
	case ResourceWireGuardTransport, ResourcePlainTransport:
		if record.Prefix != "" {
			if _, err := netip.ParsePrefix(record.Prefix); err != nil {
				return fmt.Errorf("%w: transport prefix %q: %v", ErrInvalidResource, record.Prefix, err)
			}
		}
	}
	return nil
}

func validExactName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name {
		return false
	}
	if strings.ContainsAny(name, "*?[]") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func sameResourceKey(a, b ResourceKey) bool { return a == b }

// ResourceLedger is the narrow persistence/ownership boundary used by Mesh.
// Tests can use MemoryLedger; production uses FileLedger.
type ResourceLedger interface {
	Records() []ResourceRecord
	Add(ResourceRecord) error
	UpdateState(ResourceKey, CleanupState, error) error
	Remove(ResourceKey) error
	Recover(currentInstanceID string, cleaner Cleaner) RecoveryStatus
}

type ledgerState struct {
	mu      sync.Mutex
	owner   string
	path    string
	records []ResourceRecord
	persist func([]ResourceRecord) error
	failure error
}

func (s *ledgerState) Path() string { return s.path }

func (s *ledgerState) Records() []ResourceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordsCopyLocked()
}

func (s *ledgerState) recordsCopyLocked() []ResourceRecord {
	out := append([]ResourceRecord(nil), s.records...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.InstanceID != b.InstanceID {
			return a.InstanceID < b.InstanceID
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Prefix != b.Prefix {
			return a.Prefix < b.Prefix
		}
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		return a.ParentID < b.ParentID
	})
	return out
}

func (s *ledgerState) saveLocked() error {
	if s.failure != nil {
		return s.failure
	}
	if s.persist == nil {
		return nil
	}
	return s.persist(s.recordsCopyLocked())
}

func (s *ledgerState) Add(record ResourceRecord) error {
	if record.Owner == "" {
		record.Owner = s.owner
	}
	if record.Owner != s.owner {
		return fmt.Errorf("%w: record owner does not match current user", ErrResourceNotOwned)
	}
	if record.CleanupState == "" {
		record.CleanupState = CleanupActive
	}
	if err := validateResourceRecord(record); err != nil {
		return err
	}
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.Key()
	for _, existing := range s.records {
		if sameResourceKey(existing.Key(), key) {
			return nil
		}
	}
	s.records = append(s.records, record)
	if err := s.saveLocked(); err != nil {
		s.records = s.records[:len(s.records)-1]
		return fmt.Errorf("persist resource record: %w", err)
	}
	return nil
}

func (s *ledgerState) UpdateState(key ResourceKey, state CleanupState, cleanupErr error) error {
	if !state.Valid() {
		return fmt.Errorf("%w: invalid cleanup state %q", ErrInvalidResource, state)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.records {
		if !sameResourceKey(s.records[i].Key(), key) {
			continue
		}
		old := s.records[i]
		s.records[i].CleanupState = state
		s.records[i].LastError = ""
		if cleanupErr != nil {
			s.records[i].LastError = cleanupErr.Error()
		}
		s.records[i].UpdatedAt = time.Now().UTC()
		if err := s.saveLocked(); err != nil {
			s.records[i] = old
			return fmt.Errorf("persist cleanup state: %w", err)
		}
		return nil
	}
	return fmt.Errorf("%w: resource record not found", ErrInvalidResource)
}

func (s *ledgerState) Remove(key ResourceKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.records {
		if sameResourceKey(s.records[i].Key(), key) {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	removed := s.records[index]
	s.records = append(s.records[:index], s.records[index+1:]...)
	if err := s.saveLocked(); err != nil {
		s.records = append(s.records[:index], append([]ResourceRecord{removed}, s.records[index:]...)...)
		return fmt.Errorf("persist resource removal: %w", err)
	}
	return nil
}

func (s *ledgerState) Recover(currentInstanceID string, cleaner Cleaner) RecoveryStatus {
	if cleaner == nil {
		cleaner = CleanupResource
	}
	status := RecoveryStatus{CheckedAt: time.Now().UTC()}
	for _, record := range s.Records() {
		if record.InstanceID == currentInstanceID {
			continue
		}
		status.Checked++
		if record.CleanupState == CleanupCleaned {
			if record.Owner != s.owner {
				s.addRecoveryIssue(&status, record, fmt.Errorf("%w: record owner does not match current user", ErrResourceNotOwned), true)
				continue
			}
			if err := s.Remove(record.Key()); err != nil {
				s.addRecoveryIssue(&status, record, err, false)
			} else {
				status.Recovered++
			}
			continue
		}
		if err := validateRecoveryRecord(record, s.owner); err != nil {
			_ = s.UpdateState(record.Key(), CleanupUnproven, err)
			s.addRecoveryIssue(&status, record, err, true)
			continue
		}
		if err := s.UpdateState(record.Key(), CleanupPending, nil); err != nil {
			s.addRecoveryIssue(&status, record, err, false)
			continue
		}
		cleanupErr := cleaner(record)
		if cleanupErr == nil {
			if err := s.Remove(record.Key()); err != nil {
				s.addRecoveryIssue(&status, record, err, false)
			} else {
				status.Recovered++
			}
			continue
		}
		if errors.Is(cleanupErr, ErrResourceNotOwned) || errors.Is(cleanupErr, ErrResourceUnsupported) {
			_ = s.UpdateState(record.Key(), CleanupUnproven, cleanupErr)
			s.addRecoveryIssue(&status, record, cleanupErr, true)
			continue
		}
		_ = s.UpdateState(record.Key(), CleanupFailed, cleanupErr)
		s.addRecoveryIssue(&status, record, cleanupErr, false)
	}
	status.Remaining = s.Records()
	return status
}

func (s *ledgerState) addRecoveryIssue(status *RecoveryStatus, record ResourceRecord, err error, unproven bool) {
	if unproven {
		status.Unproven++
	} else {
		status.Failed++
	}
	status.Issues = append(status.Issues, ResourceRecoveryIssue{Resource: record, Error: err.Error(), Unproven: unproven})
}

func validateRecoveryRecord(record ResourceRecord, currentOwner string) error {
	if err := validateResourceRecord(record); err != nil {
		return fmt.Errorf("%w: %v", ErrResourceNotOwned, err)
	}
	if record.Owner != currentOwner {
		return fmt.Errorf("%w: owner %q does not match current user", ErrResourceNotOwned, record.Owner)
	}
	return nil
}

// FileLedger persists exact ownership records in a user-private directory.
type FileLedger struct{ *ledgerState }

type ledgerFile struct {
	Version int              `json:"version"`
	Records []ResourceRecord `json:"records"`
}

const ledgerVersion = 1

func DefaultLedgerPath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return filepath.Join(root, "TLAN", "mesh-resources.json"), nil
}

func OpenDefaultLedger() (*FileLedger, error) {
	path, err := DefaultLedgerPath()
	if err != nil {
		return nil, err
	}
	return NewFileLedger(path)
}

func NewFileLedger(path string) (*FileLedger, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("resource ledger path is empty")
	}
	owner, err := CurrentOwner()
	if err != nil {
		return nil, fmt.Errorf("identify current user: %w", err)
	}
	state := &ledgerState{owner: owner, path: path}
	state.persist = func(records []ResourceRecord) error { return writeLedgerFile(path, records) }
	if err := prepareLedgerPath(path); err != nil {
		return nil, err
	}
	if err := loadLedgerFile(path, state); err != nil {
		return nil, err
	}
	return &FileLedger{ledgerState: state}, nil
}

func prepareLedgerPath(path string) error {
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect resource ledger: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("resource ledger path must not be a symbolic link")
	}
	return securePrivateFile(path)
}

func loadLedgerFile(path string, state *ledgerState) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read resource ledger: %w", err)
	}
	var file ledgerFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("decode resource ledger: %w", err)
	}
	if file.Version != 0 && file.Version != ledgerVersion {
		return fmt.Errorf("unsupported resource ledger version %d", file.Version)
	}
	state.records = append([]ResourceRecord(nil), file.Records...)
	return nil
}

func writeLedgerFile(path string, records []ResourceRecord) error {
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ledgerFile{Version: ledgerVersion, Records: records}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode resource ledger: %w", err)
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".mesh-resources-*.tmp")
	if err != nil {
		return fmt.Errorf("create resource ledger temporary file: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() { _ = os.Remove(tempName) }
	defer cleanup()
	if err := securePrivateFile(tempName); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write resource ledger: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync resource ledger: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close resource ledger: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("resource ledger path must not be a symbolic link")
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace resource ledger: %w", err)
	}
	return nil
}

// MemoryLedger is intended for tests and for injected Native data planes. It
// uses the same ownership checks as FileLedger but never touches the system.
type MemoryLedger struct{ *ledgerState }

func NewMemoryLedger() *MemoryLedger {
	owner, err := CurrentOwner()
	if err != nil {
		owner = "unknown"
	}
	return NewMemoryLedgerWithOwner(owner)
}

func NewMemoryLedgerWithOwner(owner string) *MemoryLedger {
	return &MemoryLedger{ledgerState: &ledgerState{owner: owner}}
}

// SetPersistenceError makes subsequent mutations fail, which is useful for
// testing the fail-closed cleanup contract.
func (l *MemoryLedger) SetPersistenceError(err error) {
	l.ledgerState.mu.Lock()
	l.ledgerState.failure = err
	l.ledgerState.mu.Unlock()
}

// Owner returns the user identity associated with this in-memory ledger.
func (l *MemoryLedger) Owner() string { return l.ledgerState.owner }
