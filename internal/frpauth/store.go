package frpauth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

type leaseRecord struct {
	ID             string            `json:"id"`
	CapabilityHash string            `json:"capability_hash"`
	NetworkID      string            `json:"network_id"`
	DeviceID       string            `json:"device_id"`
	ServerID       string            `json:"server_id"`
	Rules          []Rule            `json:"rules"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
	LoginUser      string            `json:"login_user,omitempty"`
	LoginRunID     string            `json:"login_run_id,omitempty"`
	RunID          string            `json:"run_id,omitempty"`
	Proxies        map[string]string `json:"proxies,omitempty"`
	LastSeen       time.Time         `json:"last_seen,omitempty"`
}

type serviceRecord struct {
	ID                string     `json:"id"`
	ServerID          string     `json:"server_id"`
	NetworkID         string     `json:"network_id"`
	DeviceID          string     `json:"device_id"`
	RequesterDeviceID string     `json:"requester_device_id,omitempty"`
	Protocol          string     `json:"protocol"`
	Port              int        `json:"port"`
	Description       string     `json:"description,omitempty"`
	ApprovalStatus    string     `json:"approval_status,omitempty"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	DeniedAt          *time.Time `json:"denied_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	Version           uint64     `json:"version"`
}

func (r serviceRecord) response() ServiceResponse {
	status := r.ApprovalStatus
	if status == "" {
		status = ServiceApprovalApproved
	}
	return ServiceResponse{
		ID: r.ID, ServerID: r.ServerID, NetworkID: r.NetworkID, DeviceID: r.DeviceID,
		RequesterDeviceID: r.RequesterDeviceID, Protocol: r.Protocol, Port: r.Port,
		Description: r.Description, ApprovalStatus: status, ApprovedAt: r.ApprovedAt, ApprovedBy: r.ApprovedBy,
		DeniedAt: r.DeniedAt, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt, Version: r.Version,
	}
}

func (r serviceRecord) approved() bool {
	return r.ApprovalStatus == "" || r.ApprovalStatus == ServiceApprovalApproved
}

type persistedState struct {
	SchemaVersion int             `json:"schema_version"`
	Leases        []leaseRecord   `json:"leases"`
	Services      []serviceRecord `json:"services,omitempty"`
}

// Store is the in-memory authorization authority backed by one atomically
// replaced JSON file. Capabilities are persisted only as SHA-256 hashes.
type Store struct {
	mu sync.Mutex

	path        string
	serverID    string
	coreVersion string
	leaseTTL      time.Duration
	limits        Limits
	ports         []PortRange
	domains       []string
	subDomainHost string
	leases        map[string]leaseRecord
	services      map[string]serviceRecord
	now           func() time.Time
}

// NewStore opens a managed authorization store. A malformed or unsupported
// state file is an error rather than an invitation to silently reset policy.
func NewStore(options Options) (*Store, error) {
	path := strings.TrimSpace(options.StatePath)
	if path == "" {
		return nil, fmt.Errorf("%w: lease state path is required", ErrInvalid)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve FRP lease state path: %w", err)
	}
	serverID := strings.TrimSpace(options.ServerID)
	if err := validateServerID(serverID); err != nil {
		return nil, err
	}
	coreVersion := strings.TrimSpace(options.CoreVersion)
	if coreVersion == "" {
		coreVersion = "0.71.1"
	}
	if coreVersion != "0.71.1" {
		return nil, fmt.Errorf("%w: unsupported FRP core version", ErrInvalid)
	}
	if len(coreVersion) > 64 || strings.ContainsAny(coreVersion, "\x00\r\n") {
		return nil, fmt.Errorf("%w: invalid FRP core version", ErrInvalid)
	}
	ttl := options.LeaseTTL
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		return nil, fmt.Errorf("%w: lease TTL exceeds maximum", ErrInvalid)
	}
	limits, err := normalizeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	ports, err := normalizePortRanges(options.AllowedPorts)
	if err != nil {
		return nil, err
	}
	domains, err := normalizeAllowedDomains(options.AllowedDomains)
	if err != nil {
		return nil, err
	}
	subDomainHost := ""
	if rawHost := strings.TrimSpace(options.SubDomainHost); rawHost != "" {
		subDomainHost, err = normalizeDomain(rawHost)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid subdomain_host", ErrInvalid)
		}
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, fmt.Errorf("create FRP lease state directory: %w", err)
	}
	_ = os.Chmod(filepath.Dir(absolute), 0o700)
	store := &Store{
		path:          absolute,
		serverID:      serverID,
		coreVersion:   coreVersion,
		leaseTTL:      ttl,
		limits:        limits,
		ports:         ports,
		domains:       domains,
		subDomainHost: subDomainHost,
		leases:        make(map[string]leaseRecord),
		services:      make(map[string]serviceRecord),
		now:           time.Now,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func normalizeAllowedDomains(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain, err := normalizeDomainSuffix(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

const (
	maxPersistedStateBytes    = 8 * 1024 * 1024
	maxPersistedLoadBytes     = 32 * 1024 * 1024
	maxLeaseRecordBytes       = 64 * 1024
	maxDeviceLeasesBytes      = 512 * 1024
	maxRetainedInactiveLeases = 512
)

func (s *Store) decodeStateFile(path string) (persistedState, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedState{}, 0, err
	}
	return s.decodeStateBytes(data)
}

func (s *Store) decodeStateBytes(data []byte) (persistedState, int, error) {
	if len(data) > maxPersistedLoadBytes {
		return persistedState{}, len(data), fmt.Errorf("%w: FRP lease state exceeds size limit", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state persistedState
	if err := decoder.Decode(&state); err != nil {
		return persistedState{}, len(data), fmt.Errorf("decode FRP lease state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return persistedState{}, len(data), fmt.Errorf("decode FRP lease state: %w", err)
	}
	if state.SchemaVersion != SchemaVersion {
		return persistedState{}, len(data), fmt.Errorf("%w: unsupported FRP lease state schema", ErrInvalid)
	}
	if len(state.Leases) > MaxPersistedLeaseRecords {
		return persistedState{}, len(data), fmt.Errorf("%w: too many persisted FRP leases", ErrInvalid)
	}
	seenLeases := make(map[string]struct{}, len(state.Leases))
	for _, record := range state.Leases {
		if err := s.validateLoadedRecord(record); err != nil {
			return persistedState{}, len(data), fmt.Errorf("invalid persisted FRP lease %q: %w", record.ID, err)
		}
		if _, exists := seenLeases[record.ID]; exists {
			return persistedState{}, len(data), fmt.Errorf("%w: duplicate persisted lease id", ErrInvalid)
		}
		seenLeases[record.ID] = struct{}{}
	}
	if len(state.Services) > MaxPersistedServiceRecords {
		return persistedState{}, len(data), fmt.Errorf("%w: too many persisted FRP services", ErrInvalid)
	}
	seenServices := make(map[string]struct{}, len(state.Services))
	for _, service := range state.Services {
		if err := validateServiceRecord(service); err != nil {
			return persistedState{}, len(data), fmt.Errorf("invalid persisted FRP service %q: %w", service.ID, err)
		}
		if service.ServerID != s.serverID {
			return persistedState{}, len(data), fmt.Errorf("%w: service authorization belongs to a different server", ErrUnauthorized)
		}
		if _, exists := seenServices[service.ID]; exists {
			return persistedState{}, len(data), fmt.Errorf("%w: duplicate persisted service id", ErrInvalid)
		}
		seenServices[service.ID] = struct{}{}
	}
	return state, len(data), nil
}

func (s *Store) load() error {
	recoveredFromBackup := false
	state, rawSize, err := s.decodeStateFile(s.path)
	if err != nil {
		bakState, bakSize, bakErr := s.decodeStateFile(s.path + ".bak")
		if bakErr != nil {
			if errors.Is(err, os.ErrNotExist) && errors.Is(bakErr, os.ErrNotExist) {
				return nil
			}
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read FRP lease state: %w", err)
			}
			return fmt.Errorf("read FRP lease state: %w", err)
		}
		state, rawSize, recoveredFromBackup = bakState, bakSize, true
	}
	for _, record := range state.Leases {
		if record.Proxies == nil {
			record.Proxies = make(map[string]string)
		}
		s.leases[record.ID] = record
	}
	for _, service := range state.Services {
		s.services[service.ID] = service
	}
	oversized := rawSize > maxPersistedStateBytes
	if oversized {
		s.pruneLocked(s.now().UTC())
	}
	if err := s.reconcileLoadedPolicyLocked(); err != nil {
		return err
	}
	if recoveredFromBackup {
		if err := s.persistLockedWithBackup(false); err != nil {
			return err
		}
	} else if oversized {
		if err := s.persistLocked(); err != nil {
			return err
		}
	}
	_ = os.Chmod(s.path, 0o600)
	return nil
}

// reconcileLoadedPolicyLocked keeps startup independent from historical policy
// values. Persisted leases remain structurally valid, but an active lease whose
// port, domain, or quota is no longer permitted by the current configuration is
// revoked before the service starts. This prevents an allowlist reduction from
// making the control service crash-loop while still failing closed.
func (s *Store) reconcileLoadedPolicyLocked() error {
	now := s.now().UTC()
	originals := make(map[string]leaseRecord)
	for id, record := range s.leases {
		if record.RevokedAt != nil || !now.Before(record.ExpiresAt) {
			continue
		}
		if _, err := validateRules(record.Rules, s.limits, s.ports, s.domains, s.subDomainHost, true); err != nil {
			originals[id] = record.clone()
			record.RevokedAt = &now
			record.LastSeen = now
			s.leases[id] = record
		}
	}
	if len(originals) == 0 {
		return nil
	}
	if err := s.persistLocked(); err != nil {
		for id, original := range originals {
			s.leases[id] = original
		}
		return fmt.Errorf("persist revoked out-of-policy FRP leases: %w", err)
	}
	return nil
}
func serviceProtocolMatches(serviceProtocol, proxyType string) bool {
	serviceProtocol = strings.ToLower(strings.TrimSpace(serviceProtocol))
	proxyType = strings.ToLower(strings.TrimSpace(proxyType))
	switch proxyType {
	case "stcp", "xtcp", "tcpmux":
		// These proxy types carry a TCP byte stream to the target. HTTP
		// and HTTPS targets may also be authorized explicitly by an
		// administrator.
		return serviceProtocol == "tcp" || serviceProtocol == proxyType
	case "sudp":
		return serviceProtocol == "udp" || serviceProtocol == "sudp"
	case "http", "https":
		return serviceProtocol == "tcp" || serviceProtocol == proxyType
	default:
		return serviceProtocol == proxyType
	}
}
func validateServiceRecord(service serviceRecord) error {
	if err := validateID(service.ID, "service id"); err != nil {
		return err
	}
	if err := validateNetworkDevice(service.NetworkID, service.DeviceID); err != nil {
		return err
	}
	service.Protocol = strings.ToLower(strings.TrimSpace(service.Protocol))
	if service.Protocol != "tcp" && service.Protocol != "udp" && service.Protocol != "http" && service.Protocol != "https" && service.Protocol != "stcp" && service.Protocol != "sudp" && service.Protocol != "tcpmux" && service.Protocol != "xtcp" {
		return fmt.Errorf("%w: invalid service protocol", ErrInvalid)
	}
	if service.Port < 1 || service.Port > 65535 {
		return fmt.Errorf("%w: invalid service port", ErrInvalid)
	}
	if service.CreatedAt.IsZero() || service.ExpiresAt.IsZero() || !service.ExpiresAt.After(service.CreatedAt) {
		return fmt.Errorf("%w: invalid service lifetime", ErrInvalid)
	}
	if len(service.Description) > 256 || strings.ContainsAny(service.Description, "\x00\r\n") {
		return fmt.Errorf("%w: invalid service description", ErrInvalid)
	}
	if service.RequesterDeviceID != "" {
		if _, err := core.NewDeviceID(service.RequesterDeviceID); err != nil {
			return fmt.Errorf("%w: invalid requester device id", ErrInvalid)
		}
		if service.RequesterDeviceID == service.DeviceID {
			return fmt.Errorf("%w: requester and target device must differ", ErrInvalid)
		}
	}
	switch service.ApprovalStatus {
	case "", ServiceApprovalPending, ServiceApprovalApproved, ServiceApprovalDenied:
	default:
		return fmt.Errorf("%w: invalid service approval status", ErrInvalid)
	}
	if service.ApprovalStatus == ServiceApprovalDenied && service.DeniedAt == nil {
		return fmt.Errorf("%w: denied service is missing denied_at", ErrInvalid)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func (s *Store) validateLoadedRecord(record leaseRecord) error {
	if err := validateLeaseID(record.ID); err != nil {
		return err
	}
	if len(record.CapabilityHash) != 64 {
		return fmt.Errorf("%w: invalid capability hash", ErrInvalid)
	}
	if _, err := hex.DecodeString(record.CapabilityHash); err != nil {
		return fmt.Errorf("%w: invalid capability hash", ErrInvalid)
	}
	if record.ServerID != s.serverID {
		return fmt.Errorf("%w: lease belongs to a different server", ErrUnauthorized)
	}
	if err := validateNetworkDevice(record.NetworkID, record.DeviceID); err != nil {
		return err
	}
	if _, err := validateRules(record.Rules, s.limits, s.ports, s.domains, s.subDomainHost, false); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() || record.ExpiresAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return fmt.Errorf("%w: invalid lease lifetime", ErrInvalid)
	}
	if len(record.LoginUser) > 256 || len(record.LoginRunID) > 256 || len(record.RunID) > 256 {
		return fmt.Errorf("%w: persisted session identity is too long", ErrInvalid)
	}
	for name := range record.Proxies {
		if err := validateProxyName(name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) buildPersistedState() persistedState {
	state := persistedState{
		SchemaVersion: SchemaVersion,
		Leases:        make([]leaseRecord, 0, len(s.leases)),
		Services:      make([]serviceRecord, 0, len(s.services)),
	}
	for _, record := range s.leases {
		state.Leases = append(state.Leases, record.clone())
	}
	for _, service := range s.services {
		state.Services = append(state.Services, service)
	}
	sort.Slice(state.Leases, func(i, j int) bool {
		if state.Leases[i].CreatedAt.Equal(state.Leases[j].CreatedAt) {
			return state.Leases[i].ID < state.Leases[j].ID
		}
		return state.Leases[i].CreatedAt.Before(state.Leases[j].CreatedAt)
	})
	sort.Slice(state.Services, func(i, j int) bool {
		if state.Services[i].CreatedAt.Equal(state.Services[j].CreatedAt) {
			return state.Services[i].ID < state.Services[j].ID
		}
		return state.Services[i].CreatedAt.Before(state.Services[j].CreatedAt)
	})
	return state
}

func (s *Store) persistLocked() error {
	return s.persistLockedWithBackup(true)
}

func (s *Store) persistLockedWithBackup(backup bool) error {
	data, err := json.MarshalIndent(s.buildPersistedState(), "", "  ")
	if err != nil {
		return fmt.Errorf("encode FRP lease state: %w", err)
	}
	payload := append(data, '\n')
	if len(payload) > maxPersistedStateBytes {
		now := s.now().UTC()
		for id, record := range s.leases {
			if !s.activeAt(record, now) {
				delete(s.leases, id)
			}
		}
		for id, service := range s.services {
			if service.RevokedAt != nil || !now.Before(service.ExpiresAt) || service.ApprovalStatus == ServiceApprovalDenied {
				delete(s.services, id)
			}
		}
		data, err = json.MarshalIndent(s.buildPersistedState(), "", "  ")
		if err != nil {
			return fmt.Errorf("encode FRP lease state: %w", err)
		}
		payload = append(data, '\n')
		if len(payload) > maxPersistedStateBytes {
			return fmt.Errorf("%w: FRP lease state exceeds size limit", ErrQuota)
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("prepare FRP lease state dir: %w", err)
	}
	if backup {
		if err := s.writeBackupLocked(); err != nil {
			return err
		}
	}
	return writeAtomicStateFile(s.path, payload)
}

func (s *Store) writeBackupLocked() error {
	existing, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current FRP lease state for backup: %w", err)
	}
	if len(existing) == 0 || len(existing) > maxPersistedLoadBytes {
		return nil
	}
	// Keep the last readable backup if the primary was damaged outside this
	// process. Copying it here would overwrite the only recoverable snapshot
	// with bytes that load() cannot decode either.
	if _, _, err := s.decodeStateBytes(existing); err != nil {
		return nil
	}
	return writeAtomicStateFile(s.path+".bak", existing)
}

func writeAtomicStateFile(target string, payload []byte) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("write FRP lease state: %w", err)
	}
	tmp := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write FRP lease state: %w", err)
	}
	if _, err := tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write FRP lease state: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write FRP lease state: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("write FRP lease state: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("commit FRP lease state: %w", err)
	}
	cleanup = false
	_ = os.Chmod(target, 0o600)
	return nil
}

func (s *Store) pruneLocked(now time.Time) {
	var inactive []leaseRecord
	for id, record := range s.leases {
		old := false
		if record.RevokedAt != nil {
			old = now.Sub(*record.RevokedAt) > DefaultRetention
		} else {
			old = now.Sub(record.ExpiresAt) > DefaultRetention
		}
		if old {
			delete(s.leases, id)
		} else if !s.activeAt(record, now) {
			inactive = append(inactive, record)
		}
	}
	if len(inactive) > maxRetainedInactiveLeases {
		sort.Slice(inactive, func(i, j int) bool {
			ti := inactive[i].ExpiresAt
			if inactive[i].RevokedAt != nil {
				ti = *inactive[i].RevokedAt
			}
			tj := inactive[j].ExpiresAt
			if inactive[j].RevokedAt != nil {
				tj = *inactive[j].RevokedAt
			}
			if ti.Equal(tj) {
				return inactive[i].ID < inactive[j].ID
			}
			return ti.Before(tj)
		})
		for _, drop := range inactive[:len(inactive)-maxRetainedInactiveLeases] {
			delete(s.leases, drop.ID)
		}
	}
	for id, service := range s.services {
		old := false
		if service.RevokedAt != nil {
			old = now.Sub(*service.RevokedAt) > DefaultRetention
		} else {
			old = now.Sub(service.ExpiresAt) > DefaultRetention
		}
		if old {
			delete(s.services, id)
		}
	}
}

func (s *Store) activeAt(record leaseRecord, now time.Time) bool {
	return record.RevokedAt == nil && now.Before(record.ExpiresAt)
}

// Issue creates a short-lived lease after checking member ownership and all
// server-side port/domain/proxy-name conflicts. The returned capability is the
// only time the plaintext credential is available.
// ActiveLeaseCount returns the number of unexpired, unrevoked leases matching
// the optional network and device filters. Empty filters match all records.
func (s *Store) ActiveLeaseCount(networkID, deviceID string) int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.leases {
		if networkID != "" && record.NetworkID != networkID {
			continue
		}
		if deviceID != "" && record.DeviceID != deviceID {
			continue
		}
		if s.activeAt(record, now) {
			count++
		}
	}
	return count
}
func leaseRecordSize(record leaseRecord) (int, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return 0, fmt.Errorf("measure FRP lease size: %w", err)
	}
	return len(data), nil
}

func (s *Store) Issue(networkID, deviceID, serverID string, rules []Rule) (LeaseResponse, error) {
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return LeaseResponse{}, err
	}
	if strings.TrimSpace(serverID) != s.serverID {
		return LeaseResponse{}, fmt.Errorf("%w: server_id does not match this managed FRP server", ErrInvalid)
	}
	normalizedRules, err := validateRules(rules, s.limits, s.ports, s.domains, s.subDomainHost, true)
	if err != nil {
		return LeaseResponse{}, err
	}
	now := s.now().UTC()
	leaseID, err := newRandomSecret("lease_", 18)
	if err != nil {
		return LeaseResponse{}, err
	}
	capability, err := newRandomSecret("cap_", 32)
	if err != nil {
		return LeaseResponse{}, err
	}
	record := leaseRecord{
		ID:             leaseID,
		CapabilityHash: capabilityHash(capability),
		NetworkID:      networkID,
		DeviceID:       deviceID,
		ServerID:       s.serverID,
		Rules:          normalizedRules,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.leaseTTL),
		Proxies:        make(map[string]string),
	}
	recBytes, err := leaseRecordSize(record)
	if err != nil {
		return LeaseResponse{}, err
	}
	if recBytes > maxLeaseRecordBytes {
		return LeaseResponse{}, fmt.Errorf("%w: lease exceeds per-lease byte limit", ErrQuota)
	}
	newProxyNames := make(map[string]struct{}, len(normalizedRules))
	for _, rule := range normalizedRules {
		newProxyNames[rule.ProxyName] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	superseded := make(map[string]leaseRecord)
	restoreSuperseded := func() {
		for id, orig := range superseded {
			s.leases[id] = orig
		}
	}
	for id, existing := range s.leases {
		if existing.NetworkID != networkID || existing.DeviceID != deviceID || !s.activeAt(existing, now) {
			continue
		}
		overlaps := false
		for _, rule := range existing.Rules {
			if _, ok := newProxyNames[rule.ProxyName]; ok {
				overlaps = true
				break
			}
		}
		if overlaps {
			superseded[id] = existing.clone()
			existing.RevokedAt = &now
			existing.LastSeen = now
			s.leases[id] = existing
		}
	}
	for i := range normalizedRules {
		rule := &normalizedRules[i]
		if rule.TargetKind != "mesh_peer" && rule.TargetKind != "mesh_self" {
			continue
		}
		if rule.TargetServiceID != "" {
			service, ok := s.services[rule.TargetServiceID]
			if !ok || service.ServerID != s.serverID || service.NetworkID != networkID || service.DeviceID != rule.TargetDeviceID ||
				!serviceProtocolMatches(service.Protocol, rule.Type) || service.Port != rule.BindPort ||
				service.RevokedAt != nil || !service.approved() || !now.Before(service.ExpiresAt) ||
				(service.RequesterDeviceID != "" && service.RequesterDeviceID != deviceID) {
				restoreSuperseded()
				return LeaseResponse{}, fmt.Errorf("%w: target service authorization is missing, pending, denied, expired or mismatched", ErrUnauthorized)
			}
		} else if rule.TargetKind == "mesh_peer" {
			restoreSuperseded()
			return LeaseResponse{}, fmt.Errorf("%w: mesh_peer target service authorization is required", ErrUnauthorized)
		}
		grantID, err := newRandomSecret("grant_", 18)
		if err != nil {
			restoreSuperseded()
			return LeaseResponse{}, err
		}
		rule.GrantID = grantID
	}
	// Recompute size after GrantID assignment.
	recBytes, err = leaseRecordSize(record)
	if err != nil {
		restoreSuperseded()
		return LeaseResponse{}, err
	}
	if recBytes > maxLeaseRecordBytes {
		restoreSuperseded()
		return LeaseResponse{}, fmt.Errorf("%w: lease exceeds per-lease byte limit", ErrQuota)
	}
	deviceBytes := recBytes
	for _, existing := range s.leases {
		if existing.DeviceID == deviceID && s.activeAt(existing, now) {
			sz, szErr := leaseRecordSize(existing)
			if szErr != nil {
				restoreSuperseded()
				return LeaseResponse{}, szErr
			}
			deviceBytes += sz
			if deviceBytes > maxDeviceLeasesBytes {
				restoreSuperseded()
				return LeaseResponse{}, fmt.Errorf("%w: device lease storage limit reached", ErrQuota)
			}
		}
	}
	if len(s.leases) >= MaxPersistedLeaseRecords {
		restoreSuperseded()
		return LeaseResponse{}, fmt.Errorf("%w: too many persisted FRP leases", ErrQuota)
	}
	if err := s.checkQuotaAndConflictsLocked(record); err != nil {
		restoreSuperseded()
		return LeaseResponse{}, err
	}
	s.leases[leaseID] = record
	if err := s.persistLocked(); err != nil {
		delete(s.leases, leaseID)
		restoreSuperseded()
		return LeaseResponse{}, err
	}
	return record.response(capability), nil
}

func (s *Store) checkQuotaAndConflictsLocked(record leaseRecord) error {
	now := s.now().UTC()
	deviceLeases := 0
	devicePorts := make(map[string]struct{})
	deviceDomains := make(map[string]struct{})
	allProxyNames := make(map[string]struct{})
	allPorts := make(map[string]struct{})
	allDomains := make(map[string]struct{})
	for _, existing := range s.leases {
		if !s.activeAt(existing, now) {
			continue
		}
		for _, rule := range existing.Rules {
			allProxyNames[rule.ProxyName] = struct{}{}
			if rule.RemotePort != 0 {
				allPorts[rule.Type+":"+fmt.Sprint(rule.RemotePort)] = struct{}{}
			}
			for _, domain := range ruleDomainKeys(rule, s.subDomainHost) {
				allDomains[domain] = struct{}{}
			}
		}
		if existing.DeviceID != record.DeviceID {
			continue
		}
		deviceLeases++
		for _, rule := range existing.Rules {
			if rule.RemotePort != 0 {
				devicePorts[rule.Type+":"+fmt.Sprint(rule.RemotePort)] = struct{}{}
			}
			for _, domain := range ruleDomainKeys(rule, s.subDomainHost) {
				deviceDomains[domain] = struct{}{}
			}
		}
	}
	if deviceLeases >= s.limits.MaxLeasesPerDevice {
		return fmt.Errorf("%w: device lease limit reached", ErrQuota)
	}
	newPorts := make(map[string]struct{})
	newDomains := make(map[string]struct{})
	for _, rule := range record.Rules {
		if _, exists := allProxyNames[rule.ProxyName]; exists {
			return fmt.Errorf("%w: proxy_name is already leased", ErrConflict)
		}
		if rule.RemotePort != 0 {
			key := rule.Type + ":" + fmt.Sprint(rule.RemotePort)
			if _, exists := allPorts[key]; exists {
				return fmt.Errorf("%w: remote_port is already leased for this protocol", ErrConflict)
			}
			newPorts[key] = struct{}{}
		}
		for _, domain := range ruleDomainKeys(rule, s.subDomainHost) {
			if _, exists := allDomains[domain]; exists {
				return fmt.Errorf("%w: custom domain/subdomain is already leased", ErrConflict)
			}
			newDomains[domain] = struct{}{}
		}
	}
	if len(devicePorts)+len(newPorts) > s.limits.MaxPortsPerDevice {
		return fmt.Errorf("%w: device port limit reached", ErrQuota)
	}
	if len(deviceDomains)+len(newDomains) > s.limits.MaxDomainsPerDevice {
		return fmt.Errorf("%w: device domain limit reached", ErrQuota)
	}
	return nil
}

// Revoke marks a lease revoked and persists a tombstone. It is idempotent for
// the owning member, but never reveals whether another member's lease exists.
func (s *Store) Revoke(leaseID, networkID, deviceID string) error {
	if err := validateLeaseID(leaseID); err != nil {
		return err
	}
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.leases[leaseID]
	if !ok || record.NetworkID != networkID || record.DeviceID != deviceID {
		return ErrNotFound
	}
	if record.RevokedAt != nil {
		return nil
	}
	original := record.clone()
	now := s.now().UTC()
	record.RevokedAt = &now
	record.LastSeen = now
	s.leases[leaseID] = record
	s.pruneLocked(now)
	if err := s.persistLocked(); err != nil {
		s.leases[leaseID] = original
		return err
	}
	return nil
}

// IssueService creates an administrator-managed target-service authorization.
// It is the explicit grant that lets another member request a mesh_peer lease.
// Administrator-issued grants remain immediately approved for compatibility.
func (s *Store) IssueService(networkID, deviceID, serviceID, protocol string, port int, description string, ttl time.Duration) (ServiceResponse, error) {
	return s.issueService(networkID, deviceID, "", serviceID, protocol, port, description, ttl, ServiceApprovalApproved)
}

// RequestService creates a pending target-service request. The target member
// must approve it before any lease can reference the service ID.
func (s *Store) RequestService(networkID, targetDeviceID, requesterDeviceID, serviceID, protocol string, port int, description string, ttl time.Duration) (ServiceResponse, error) {
	if err := validateNetworkDevice(networkID, requesterDeviceID); err != nil {
		return ServiceResponse{}, err
	}
	if targetDeviceID == requesterDeviceID {
		return ServiceResponse{}, fmt.Errorf("%w: requester cannot target its own device", ErrInvalid)
	}
	return s.issueService(networkID, targetDeviceID, requesterDeviceID, serviceID, protocol, port, description, ttl, ServiceApprovalPending)
}

func (s *Store) issueService(networkID, deviceID, requesterDeviceID, serviceID, protocol string, port int, description string, ttl time.Duration, approvalStatus string) (ServiceResponse, error) {
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return ServiceResponse{}, err
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" && protocol != "http" && protocol != "https" && protocol != "stcp" && protocol != "sudp" && protocol != "tcpmux" && protocol != "xtcp" {
		return ServiceResponse{}, fmt.Errorf("%w: unsupported service protocol", ErrInvalid)
	}
	if port < 1 || port > 65535 {
		return ServiceResponse{}, fmt.Errorf("%w: service port must be 1-65535", ErrInvalid)
	}
	description = strings.TrimSpace(description)
	if len(description) > 256 || strings.ContainsAny(description, "\x00\r\n") {
		return ServiceResponse{}, fmt.Errorf("%w: invalid service description", ErrInvalid)
	}
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		var err error
		serviceID, err = newRandomSecret("svc_", 18)
		if err != nil {
			return ServiceResponse{}, err
		}
	}
	if err := validateID(serviceID, "service id"); err != nil {
		return ServiceResponse{}, err
	}
	if ttl <= 0 {
		ttl = DefaultRetention
	}
	if approvalStatus == ServiceApprovalPending && ttl > MaxPendingServiceTTL {
		return ServiceResponse{}, fmt.Errorf("%w: pending service lifetime exceeds 24h maximum", ErrInvalid)
	}
	if ttl > 30*24*time.Hour {
		return ServiceResponse{}, fmt.Errorf("%w: service lifetime exceeds maximum", ErrInvalid)
	}
	now := s.now().UTC()
	service := serviceRecord{
		ID: serviceID, ServerID: s.serverID, NetworkID: networkID, DeviceID: deviceID,
		RequesterDeviceID: requesterDeviceID, Protocol: protocol, Port: port,
		Description: description, ApprovalStatus: approvalStatus,
		CreatedAt: now, ExpiresAt: now.Add(ttl), Version: 1,
	}
	if approvalStatus == ServiceApprovalApproved {
		service.ApprovedAt = &now
	}
	if err := validateServiceRecord(service); err != nil {
		return ServiceResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if approvalStatus == ServiceApprovalPending {
		requesterPending := 0
		targetPending := 0
		for id, existing := range s.services {
			if existing.ApprovalStatus != ServiceApprovalPending || existing.RevokedAt != nil || !now.Before(existing.ExpiresAt) {
				continue
			}
			if existing.NetworkID == networkID && existing.DeviceID == deviceID && existing.RequesterDeviceID == requesterDeviceID &&
				existing.Protocol == protocol && existing.Port == port {
				original := existing
				existing.Description = description
				existing.ExpiresAt = now.Add(ttl)
				existing.Version++
				s.services[id] = existing
				if err := s.persistLocked(); err != nil {
					s.services[id] = original
					return ServiceResponse{}, err
				}
				return existing.response(), nil
			}
			if existing.NetworkID == networkID && existing.RequesterDeviceID == requesterDeviceID {
				requesterPending++
			}
			if existing.NetworkID == networkID && existing.DeviceID == deviceID {
				targetPending++
			}
		}
		if requesterPending >= MaxPendingServicesPerRequester {
			return ServiceResponse{}, fmt.Errorf("%w: too many pending service requests for requester", ErrQuota)
		}
		if targetPending >= MaxPendingServicesPerTarget {
			return ServiceResponse{}, fmt.Errorf("%w: too many pending service requests for target", ErrQuota)
		}
	}
	if _, exists := s.services[serviceID]; exists {
		return ServiceResponse{}, fmt.Errorf("%w: service id already exists", ErrConflict)
	}
	if len(s.services) >= MaxPersistedServiceRecords {
		return ServiceResponse{}, fmt.Errorf("%w: too many service authorizations", ErrQuota)
	}
	s.services[serviceID] = service
	if err := s.persistLocked(); err != nil {
		delete(s.services, serviceID)
		return ServiceResponse{}, err
	}
	return service.response(), nil
}

// ApproveService lets the exact target member approve a pending service.
func (s *Store) ApproveService(serviceID, networkID, targetDeviceID string) (ServiceResponse, error) {
	if err := validateID(serviceID, "service id"); err != nil {
		return ServiceResponse{}, err
	}
	if err := validateNetworkDevice(networkID, targetDeviceID); err != nil {
		return ServiceResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	service, ok := s.services[serviceID]
	if !ok || service.NetworkID != networkID || service.DeviceID != targetDeviceID {
		return ServiceResponse{}, ErrNotFound
	}
	if service.RevokedAt != nil {
		return ServiceResponse{}, ErrRevoked
	}
	if service.ApprovalStatus == ServiceApprovalApproved {
		return service.response(), nil
	}
	if service.ApprovalStatus != ServiceApprovalPending {
		return ServiceResponse{}, fmt.Errorf("%w: service request is not pending", ErrConflict)
	}
	now := s.now().UTC()
	if !now.Before(service.ExpiresAt) {
		return ServiceResponse{}, ErrExpired
	}
	original := service
	service.ApprovalStatus = ServiceApprovalApproved
	service.ApprovedAt = &now
	service.ApprovedBy = targetDeviceID
	service.DeniedAt = nil
	service.Version++
	s.services[serviceID] = service
	if err := s.persistLocked(); err != nil {
		s.services[serviceID] = original
		return ServiceResponse{}, err
	}
	return service.response(), nil
}

// DenyService rejects a pending service request and revokes any leases that
// somehow reference it. Only the exact target member can deny the request.
func (s *Store) DenyService(serviceID, networkID, targetDeviceID string) (ServiceResponse, error) {
	if err := validateID(serviceID, "service id"); err != nil {
		return ServiceResponse{}, err
	}
	if err := validateNetworkDevice(networkID, targetDeviceID); err != nil {
		return ServiceResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	service, ok := s.services[serviceID]
	if !ok || service.NetworkID != networkID || service.DeviceID != targetDeviceID {
		return ServiceResponse{}, ErrNotFound
	}
	if service.RevokedAt != nil {
		return ServiceResponse{}, ErrRevoked
	}
	original := service
	now := s.now().UTC()
	service.ApprovalStatus = ServiceApprovalDenied
	service.DeniedAt = &now
	service.RevokedAt = &now
	service.Version++
	s.services[serviceID] = service
	changedLeases := make(map[string]leaseRecord)
	for id, lease := range s.leases {
		if lease.RevokedAt != nil {
			continue
		}
		for _, rule := range lease.Rules {
			if rule.TargetServiceID != serviceID {
				continue
			}
			changedLeases[id] = lease.clone()
			lease.RevokedAt = &now
			lease.LastSeen = now
			s.leases[id] = lease
			break
		}
	}
	if err := s.persistLocked(); err != nil {
		s.services[serviceID] = original
		for id, lease := range changedLeases {
			s.leases[id] = lease
		}
		return ServiceResponse{}, err
	}
	return service.response(), nil
}

// ListPendingServices returns pending requests for the exact target member.
func (s *Store) ListPendingServices(networkID, targetDeviceID string) ([]ServiceResponse, error) {
	if err := validateNetworkDevice(networkID, targetDeviceID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	out := make([]ServiceResponse, 0)
	for _, service := range s.services {
		if service.NetworkID != networkID || service.DeviceID != targetDeviceID ||
			service.ApprovalStatus != ServiceApprovalPending || service.RevokedAt != nil || !now.Before(service.ExpiresAt) {
			continue
		}
		out = append(out, service.response())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// RevokeService revokes a target-service authorization by ID. Existing leases
// remain until their own revocation/expiry, but no new lease can reference it.
func (s *Store) RevokeService(serviceID string) error {
	if err := validateID(serviceID, "service id"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeServiceLocked(serviceID)
}

// RevokeServiceByTarget lets the exact target member withdraw a previously
// approved or pending service authorization.
func (s *Store) RevokeServiceByTarget(serviceID, networkID, targetDeviceID string) error {
	if err := validateID(serviceID, "service id"); err != nil {
		return err
	}
	if err := validateNetworkDevice(networkID, targetDeviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	service, ok := s.services[serviceID]
	if !ok || service.NetworkID != networkID || service.DeviceID != targetDeviceID {
		return ErrNotFound
	}
	return s.revokeServiceLocked(serviceID)
}

func (s *Store) revokeServiceLocked(serviceID string) error {
	service, ok := s.services[serviceID]
	if !ok {
		return ErrNotFound
	}
	if service.RevokedAt != nil {
		return nil
	}
	original := service
	now := s.now().UTC()
	service.RevokedAt = &now
	service.Version++
	s.services[serviceID] = service
	changedLeases := make(map[string]leaseRecord)
	for id, lease := range s.leases {
		if lease.RevokedAt != nil {
			continue
		}
		for _, rule := range lease.Rules {
			if rule.TargetServiceID != serviceID {
				continue
			}
			changedLeases[id] = lease.clone()
			lease.RevokedAt = &now
			lease.LastSeen = now
			s.leases[id] = lease
			break
		}
	}
	if err := s.persistLocked(); err != nil {
		s.services[serviceID] = original
		for id, lease := range changedLeases {
			s.leases[id] = lease
		}
		return err
	}
	return nil
}

// ListServices returns target-service authorizations for one member.
func (s *Store) ListServices(networkID, deviceID string) ([]ServiceResponse, error) {
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	out := make([]ServiceResponse, 0)
	for _, service := range s.services {
		if service.NetworkID != networkID || service.DeviceID != deviceID {
			continue
		}
		if service.RevokedAt == nil && !now.Before(service.ExpiresAt) {
			continue
		}
		out = append(out, service.response())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListRequestedServices returns services requested by one publisher so the
// publisher can show pending, approved, denied and expired request states.
func (s *Store) ListRequestedServices(networkID, requesterDeviceID string) ([]ServiceResponse, error) {
	if err := validateNetworkDevice(networkID, requesterDeviceID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ServiceResponse, 0)
	for _, service := range s.services {
		if service.NetworkID != networkID || service.RequesterDeviceID != requesterDeviceID {
			continue
		}
		out = append(out, service.response())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// RevokeDevice revokes every active lease owned by one member in one network.
// It keeps tombstones so stale capabilities cannot become valid again.
func (s *Store) RevokeDevice(networkID, deviceID string) error {
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	changed := make(map[string]leaseRecord)
	for id, record := range s.leases {
		if record.NetworkID != networkID || record.DeviceID != deviceID || record.RevokedAt != nil {
			continue
		}
		original := record.clone()
		record.RevokedAt = &now
		record.LastSeen = now
		s.leases[id] = record
		changed[id] = original
	}
	changedServices := make(map[string]serviceRecord)
	for id, service := range s.services {
		if service.NetworkID != networkID || service.DeviceID != deviceID || service.RevokedAt != nil {
			continue
		}
		original := service
		service.RevokedAt = &now
		service.Version++
		s.services[id] = service
		changedServices[id] = original
	}
	if len(changed) == 0 && len(changedServices) == 0 {
		return nil
	}
	if err := s.persistLocked(); err != nil {
		for id, original := range changed {
			s.leases[id] = original
		}
		for id, original := range changedServices {
			s.services[id] = original
		}
		return err
	}
	return nil
}

// Renew extends an active lease without issuing a new capability. The
// capability remains bound to the same device and lease record.
func (s *Store) Renew(leaseID, networkID, deviceID string) (LeaseResponse, error) {
	if err := validateLeaseID(leaseID); err != nil {
		return LeaseResponse{}, err
	}
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return LeaseResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.leases[leaseID]
	if !ok || record.NetworkID != networkID || record.DeviceID != deviceID {
		return LeaseResponse{}, ErrNotFound
	}
	if record.RevokedAt != nil {
		return LeaseResponse{}, ErrRevoked
	}
	now := s.now().UTC()
	if !now.Before(record.ExpiresAt) {
		return LeaseResponse{}, ErrExpired
	}
	if err := s.validateLeaseServicesLocked(record, now); err != nil {
		return LeaseResponse{}, err
	}
	original := record.clone()
	nextExpiry := now.Add(s.leaseTTL)
	if !nextExpiry.After(record.ExpiresAt) {
		nextExpiry = record.ExpiresAt.Add(time.Nanosecond)
	}
	record.ExpiresAt = nextExpiry
	record.LastSeen = now
	s.leases[leaseID] = record
	if err := s.persistLocked(); err != nil {
		s.leases[leaseID] = original
		return LeaseResponse{}, err
	}
	return LeaseResponse{LeaseID: record.ID, ExpiresAt: record.ExpiresAt, Rules: append([]Rule(nil), record.Rules...)}, nil
}

func validateSessionIdentity(user, runID string) error {
	user = strings.TrimSpace(user)
	runID = strings.TrimSpace(runID)
	if user == "" || len(user) > 256 || strings.ContainsAny(user, "\x00\r\n") {
		return fmt.Errorf("%w: invalid session user", ErrUnauthorized)
	}
	if runID == "" || len(runID) > 256 || strings.ContainsAny(runID, "\x00\r\n") {
		return fmt.Errorf("%w: invalid session run_id", ErrUnauthorized)
	}
	return nil
}

func (s *Store) authorizeSessionLocked(request SessionRequest, now time.Time) (leaseRecord, error) {
	record, err := s.authenticateLocked(request.LeaseID, request.Capability, request.ServerID, now)
	if err != nil {
		return leaseRecord{}, err
	}
	user := strings.TrimSpace(request.User)
	runID := strings.TrimSpace(request.RunID)
	if record.LoginUser == "" || record.LoginUser != user {
		return leaseRecord{}, ErrUnauthorized
	}
	if record.LoginRunID != "" && record.LoginRunID != runID {
		return leaseRecord{}, ErrUnauthorized
	}
	if record.RunID != "" && record.RunID != runID {
		return leaseRecord{}, ErrUnauthorized
	}
	return record, nil
}

// AuthorizePing revalidates a live FRPS session on every heartbeat. FRPC
// v0.71.1 closes the control connection immediately when this hook rejects;
// FRPS also closes it after the configured heartbeat timeout.
func (s *Store) AuthorizePing(request SessionRequest) error {
	if err := validateLeaseID(request.LeaseID); err != nil {
		return err
	}
	if err := validateCapability(request.Capability); err != nil {
		return err
	}
	if err := validateServerID(request.ServerID); err != nil {
		return err
	}
	if err := validateSessionIdentity(request.User, request.RunID); err != nil {
		return err
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.authorizeSessionLocked(request, now)
	if err != nil {
		return err
	}
	// Heartbeats are frequent; keep LastSeen current in memory without
	// rewriting the authorization database every few seconds.
	record.LastSeen = now
	s.leases[record.ID] = record
	return nil
}

// AuthorizeUserConn rejects new user connections immediately after a lease is
// revoked or its session identity changes. UDP traffic is covered by Ping,
// because FRP does not emit NewUserConn for UDP proxies.
func (s *Store) AuthorizeUserConn(request UserConnRequest) error {
	if err := validateLeaseID(request.LeaseID); err != nil {
		return err
	}
	if err := validateCapability(request.Capability); err != nil {
		return err
	}
	if err := validateServerID(request.ServerID); err != nil {
		return err
	}
	if err := validateSessionIdentity(request.User, request.RunID); err != nil {
		return err
	}
	proxyType := strings.ToLower(strings.TrimSpace(request.ProxyType))
	if proxyType == "" {
		return fmt.Errorf("%w: invalid proxy type", ErrUnauthorized)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.authorizeSessionLocked(SessionRequest{
		LeaseID: request.LeaseID, Capability: request.Capability, ServerID: request.ServerID,
		User: request.User, RunID: request.RunID,
	}, now)
	if err != nil {
		return err
	}
	user := strings.TrimSpace(request.User)
	for i := range record.Rules {
		leasedName := record.Rules[i].ProxyName
		if request.ProxyName != leasedName && request.ProxyName != user+"."+leasedName {
			continue
		}
		if record.Rules[i].Type != proxyType {
			return ErrUnauthorized
		}
		record.LastSeen = now
		s.leases[record.ID] = record
		return nil
	}
	return ErrUnauthorized
}

// Capabilities returns the fixed managed-control-plane contract.
func (s *Store) Capabilities() Capabilities {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Capabilities{
		Mode: ModeManaged, CoreVersion: s.coreVersion, ServerID: s.serverID,
		LeaseTTL:     int64(s.leaseTTL / time.Second),
		AllowedPorts: append([]PortRange(nil), s.ports...),
		PluginOps:    []string{"Login", "NewProxy", "Ping", "NewUserConn"},
		Features:     []string{"managed-leases", "lease-renewal", "lease-revocation", "mesh-target-grants", "target-service-authorization", "target-member-approval"},
	}
}

// AllowedPorts returns a copy of the active managed remote port allowlist.
func (s *Store) AllowedPorts() []PortRange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PortRange(nil), s.ports...)
}

// SetAllowedPorts updates the managed remote port allowlist and revokes active
// leases that violate the updated policy.
func (s *Store) SetAllowedPorts(ranges []PortRange) error {
	normalized, err := normalizePortRanges(ranges)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.ports
	s.ports = normalized
	if err := s.reconcileLoadedPolicyLocked(); err != nil {
		s.ports = prev
		return err
	}
	return nil
}

// Status reports whether FRPS has observed the lease and its proxy. It does
// not expose the capability or any other client credential.
func (s *Store) Status(leaseID, networkID, deviceID string) (LeaseStatus, error) {
	if err := validateLeaseID(leaseID); err != nil {
		return LeaseStatus{}, err
	}
	if err := validateNetworkDevice(networkID, deviceID); err != nil {
		return LeaseStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.leases[leaseID]
	if !ok || record.NetworkID != networkID || record.DeviceID != deviceID {
		return LeaseStatus{}, ErrNotFound
	}
	return LeaseStatus{
		LeaseID: record.ID, ExpiresAt: record.ExpiresAt, Revoked: record.RevokedAt != nil,
		LoginSeen: record.LoginUser != "", ProxySeen: len(record.Proxies) != 0, LastSeen: record.LastSeen,
	}, nil
}

func (s *Store) authenticateLocked(leaseID, capability, serverID string, now time.Time) (leaseRecord, error) {
	record, ok := s.leases[leaseID]
	if !ok || record.ServerID != strings.TrimSpace(serverID) ||
		!constantTimeHashMatch(record.CapabilityHash, capability) {
		return leaseRecord{}, ErrUnauthorized
	}
	if record.RevokedAt != nil {
		return leaseRecord{}, ErrRevoked
	}
	if !now.Before(record.ExpiresAt) {
		return leaseRecord{}, ErrExpired
	}
	if err := s.validateLeaseServicesLocked(record, now); err != nil {
		return leaseRecord{}, err
	}
	return record, nil
}

func (s *Store) validateLeaseServicesLocked(record leaseRecord, now time.Time) error {
	for _, rule := range record.Rules {
		if rule.TargetServiceID == "" {
			continue
		}
		service, ok := s.services[rule.TargetServiceID]
		if !ok || service.RevokedAt != nil || !service.approved() {
			return ErrRevoked
		}
		if !now.Before(service.ExpiresAt) {
			return ErrExpired
		}
		if service.ServerID != s.serverID || service.NetworkID != record.NetworkID || service.DeviceID != rule.TargetDeviceID ||
			!serviceProtocolMatches(service.Protocol, rule.Type) || service.Port != rule.BindPort {
			return ErrUnauthorized
		}
		if service.RequesterDeviceID != "" && service.RequesterDeviceID != record.DeviceID {
			return ErrUnauthorized
		}
	}
	return nil
}

// AuthorizeLogin validates the Login metadata and binds the lease to the
// client-supplied user. The authoritative run ID is checked again on NewProxy,
// where FRPS supplies the run ID it actually assigned to the session.
func (s *Store) AuthorizeLogin(request LoginRequest) error {
	if err := validateLeaseID(request.LeaseID); err != nil {
		return err
	}
	if err := validateCapability(request.Capability); err != nil {
		return err
	}
	if err := validateServerID(request.ServerID); err != nil {
		return err
	}
	user := strings.TrimSpace(request.User)
	if user == "" || len(user) > 256 || strings.ContainsAny(user, "\x00\r\n") {
		return fmt.Errorf("%w: invalid login user", ErrUnauthorized)
	}
	runID := strings.TrimSpace(request.RunID)
	if len(runID) > 256 || strings.ContainsAny(runID, "\x00\r\n") {
		return fmt.Errorf("%w: invalid run_id", ErrUnauthorized)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.authenticateLocked(request.LeaseID, request.Capability, request.ServerID, now)
	if err != nil {
		return err
	}
	if record.LoginUser != "" && record.LoginUser != user {
		return ErrUnauthorized
	}
	if runID != "" && record.LoginRunID != "" && record.LoginRunID != runID {
		return ErrUnauthorized
	}
	if runID != "" && record.RunID != "" && record.RunID != runID {
		return ErrUnauthorized
	}
	original := record.clone()
	record.LoginUser = user
	if runID != "" {
		record.LoginRunID = runID
	}
	record.LastSeen = now
	s.leases[record.ID] = record
	if err := s.persistLocked(); err != nil {
		s.leases[record.ID] = original
		return err
	}
	return nil
}

// AuthorizeNewProxy enforces every public and advanced proxy field that was
// granted by the lease. FRPS supplies HTTP passwords and private-proxy keys in
// plaintext to this plugin, so only their SHA-256 digests are compared against
// the lease; neither value is ever written to the lease store.
func (s *Store) AuthorizeNewProxy(request NewProxyRequest) error {
	if err := validateLeaseID(request.LeaseID); err != nil {
		return err
	}
	if err := validateCapability(request.Capability); err != nil {
		return err
	}
	if err := validateServerID(request.ServerID); err != nil {
		return err
	}
	user := strings.TrimSpace(request.User)
	if user == "" || len(user) > 256 || strings.ContainsAny(user, "\x00\r\n") {
		return fmt.Errorf("%w: invalid proxy user", ErrUnauthorized)
	}
	runID := strings.TrimSpace(request.RunID)
	if runID == "" || len(runID) > 256 || strings.ContainsAny(runID, "\x00\r\n") {
		return fmt.Errorf("%w: invalid proxy run_id", ErrUnauthorized)
	}
	proxyType := strings.ToLower(strings.TrimSpace(request.ProxyType))
	multiplexer := strings.ToLower(strings.TrimSpace(request.Multiplexer))
	if proxyType == "tcpmux" && multiplexer == "" {
		multiplexer = "httpconnect"
	}
	domains := make([]string, 0, len(request.CustomDomains))
	for _, raw := range request.CustomDomains {
		domain, err := normalizeDomain(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid custom domain", ErrDomainDenied)
		}
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	subDomain := strings.ToLower(strings.TrimSpace(request.SubDomain))
	if subDomain != "" {
		if err := validateSubdomainLabel(subDomain); err != nil {
			return fmt.Errorf("%w: invalid subdomain", ErrUnauthorized)
		}
	}
	locations, err := normalizeRuleLocations(request.Locations)
	if err != nil {
		return fmt.Errorf("%w: invalid locations", ErrUnauthorized)
	}
	headers, err := normalizeRuleHeaders("request headers", request.Headers)
	if err != nil {
		return fmt.Errorf("%w: invalid request headers", ErrUnauthorized)
	}
	responseHeaders, err := normalizeRuleHeaders("response headers", request.ResponseHeaders)
	if err != nil {
		return fmt.Errorf("%w: invalid response headers", ErrUnauthorized)
	}
	allowUsers, err := normalizeAllowUsers(request.AllowUsers)
	if err != nil {
		return fmt.Errorf("%w: invalid allow_users", ErrUnauthorized)
	}
	if request.Group != "" || request.GroupKey != "" || request.BandwidthLimit != "" ||
		request.BandwidthLimitMode != "" || len(request.Metas) != 0 || len(request.Annotations) != 0 {
		return ErrUnauthorized
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.authenticateLocked(request.LeaseID, request.Capability, request.ServerID, now)
	if err != nil {
		return err
	}
	if record.LoginUser == "" || record.LoginUser != user {
		return ErrUnauthorized
	}
	if record.LoginRunID != "" && record.LoginRunID != runID {
		return ErrUnauthorized
	}
	if record.RunID != "" && record.RunID != runID {
		return ErrUnauthorized
	}
	var rule *Rule
	for i := range record.Rules {
		leasedName := record.Rules[i].ProxyName
		// FRP adds "{user}." to proxy names on the wire. Accept the base
		// name for direct protocol tests and the actual wire name for a real
		// frpc, but do not accept an arbitrary prefix.
		if request.ProxyName == leasedName || request.ProxyName == user+"."+leasedName {
			rule = &record.Rules[i]
			break
		}
	}
	if rule == nil || rule.Type != proxyType {
		return ErrUnauthorized
	}
	normalized := NewProxyRequest{
		LeaseID: request.LeaseID, Capability: request.Capability, ServerID: request.ServerID,
		User: user, RunID: runID, ProxyName: request.ProxyName, ProxyType: proxyType,
		RemotePort: request.RemotePort, CustomDomains: domains, SubDomain: subDomain,
		Locations: locations, HTTPUser: strings.TrimSpace(request.HTTPUser), HTTPPwd: request.HTTPPwd,
		HostHeaderRewrite: strings.TrimSpace(request.HostHeaderRewrite), Headers: headers,
		ResponseHeaders: responseHeaders, RouteByHTTPUser: strings.TrimSpace(request.RouteByHTTPUser),
		Sk: request.Sk, AllowUsers: allowUsers, Multiplexer: multiplexer,
		UseEncryption: request.UseEncryption, UseCompression: request.UseCompression,
	}
	if err := authorizeProxyRule(*rule, normalized); err != nil {
		return err
	}
	if boundRunID, ok := record.Proxies[rule.ProxyName]; ok && boundRunID != runID {
		return fmt.Errorf("%w: proxy is bound to another session", ErrConflict)
	}
	original := record.clone()
	if record.Proxies == nil {
		record.Proxies = make(map[string]string)
	}
	record.Proxies[rule.ProxyName] = runID
	record.RunID = runID
	record.LastSeen = now
	s.leases[record.ID] = record
	if err := s.persistLocked(); err != nil {
		s.leases[record.ID] = original
		return err
	}
	return nil
}

func authorizeProxyRule(rule Rule, request NewProxyRequest) error {
	if rule.Type != request.ProxyType || rule.UseEncryption != request.UseEncryption || rule.UseCompression != request.UseCompression {
		return ErrUnauthorized
	}
	if !hashMatches(rule.SecretHash, request.Sk) {
		return ErrUnauthorized
	}
	if !sameStringSet(rule.AllowUsers, request.AllowUsers) {
		return ErrUnauthorized
	}
	switch rule.Type {
	case "tcp", "udp":
		if len(request.CustomDomains) != 0 {
			return ErrDomainDenied
		}
		if request.SubDomain != "" {
			return ErrUnauthorized
		}
		if request.RemotePort != rule.RemotePort {
			return ErrPortDenied
		}
		if requestHasAdvancedHTTPFields(request) || request.Multiplexer != "" {
			return ErrUnauthorized
		}
	case "http":
		if request.RemotePort != 0 {
			return ErrPortDenied
		}
		if !sameStringSet(request.CustomDomains, rule.CustomDomains) {
			return ErrDomainDenied
		}
		if request.SubDomain != rule.SubDomain || request.HTTPUser != rule.HTTPUser ||
			request.HostHeaderRewrite != rule.HostHeaderRewrite || request.RouteByHTTPUser != rule.RouteByHTTPUser ||
			request.Multiplexer != rule.Multiplexer || !sameStringSet(request.Locations, rule.Locations) ||
			!sameStringMap(request.Headers, rule.Headers) || !sameStringMap(request.ResponseHeaders, rule.ResponseHeaders) ||
			!hashMatches(rule.HTTPPasswordHash, request.HTTPPwd) {
			return ErrUnauthorized
		}
	case "https":
		if request.RemotePort != 0 {
			return ErrPortDenied
		}
		if !sameStringSet(request.CustomDomains, rule.CustomDomains) {
			return ErrDomainDenied
		}
		if request.SubDomain != rule.SubDomain || requestHasAdvancedHTTPFields(request) || request.Multiplexer != "" {
			return ErrUnauthorized
		}
	case "tcpmux":
		if request.RemotePort != 0 {
			return ErrPortDenied
		}
		if !sameStringSet(request.CustomDomains, rule.CustomDomains) {
			return ErrDomainDenied
		}
		if request.SubDomain != rule.SubDomain || request.HTTPUser != rule.HTTPUser ||
			request.HostHeaderRewrite != rule.HostHeaderRewrite || request.RouteByHTTPUser != rule.RouteByHTTPUser ||
			request.Multiplexer != rule.Multiplexer || len(request.Locations) != 0 ||
			len(request.Headers) != 0 || len(request.ResponseHeaders) != 0 ||
			!hashMatches(rule.HTTPPasswordHash, request.HTTPPwd) {
			return ErrUnauthorized
		}
	case "stcp", "sudp", "xtcp":
		if request.RemotePort != 0 || len(request.CustomDomains) != 0 || request.SubDomain != "" {
			return ErrUnauthorized
		}
		if requestHasAdvancedHTTPFields(request) || request.Multiplexer != "" {
			return ErrUnauthorized
		}
	default:
		return ErrUnauthorized
	}
	return nil
}

func requestHasAdvancedHTTPFields(request NewProxyRequest) bool {
	return request.HTTPUser != "" || request.HTTPPwd != "" || request.HostHeaderRewrite != "" ||
		request.RouteByHTTPUser != "" || len(request.Locations) != 0 || len(request.Headers) != 0 ||
		len(request.ResponseHeaders) != 0
}

func hashMatches(expectedHash, value string) bool {
	if expectedHash == "" {
		return value == ""
	}
	return value != "" && constantTimeHashMatch(expectedHash, value)
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
