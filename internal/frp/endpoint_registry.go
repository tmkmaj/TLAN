package frp

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

var ErrEndpointConflict = errors.New("endpoint listener conflict")

type EndpointProtocol string

const (
	EndpointProtocolTCP EndpointProtocol = "tcp"
	EndpointProtocolUDP EndpointProtocol = "udp"
)

type EndpointKind string

const (
	EndpointKindAdmin         EndpointKind = "admin"
	EndpointKindVisitor       EndpointKind = "visitor"
	EndpointKindTargetGateway EndpointKind = "target_gateway"
	EndpointKindEgressProxy   EndpointKind = "egress_proxy"
)

type EndpointState string

const (
	EndpointStateStarting EndpointState = "starting"
	EndpointStateRunning  EndpointState = "running"
)

// EndpointOwner identifies the runtime component responsible for a listener.
// InstanceGeneration prevents diagnostics or cleanup from confusing a
// replacement instance with the one it superseded.
type EndpointOwner struct {
	ProfileID          string
	InstanceScope      string
	InstanceGeneration uint64
	RuleID             string
	VisitorID          string
	Purpose            string
}

type EndpointRecord struct {
	Host     string
	Port     int
	Protocol EndpointProtocol
	Kind     EndpointKind
	State    EndpointState
	Owner    EndpointOwner
}

type EndpointConflict struct {
	Existing  EndpointRecord
	Candidate EndpointRecord
}

func (c EndpointConflict) String() string {
	return fmt.Sprintf("%s %s:%d/%s (%s) conflicts with %s %s:%d/%s (%s)",
		c.Candidate.Kind, c.Candidate.Host, c.Candidate.Port, c.Candidate.Protocol, c.Candidate.Owner.Purpose,
		c.Existing.Kind, c.Existing.Host, c.Existing.Port, c.Existing.Protocol, c.Existing.Owner.Purpose)
}

type EndpointConflictError struct {
	Conflicts []EndpointConflict
}

func (e *EndpointConflictError) Error() string {
	if e == nil || len(e.Conflicts) == 0 {
		return ErrEndpointConflict.Error()
	}
	details := make([]string, 0, len(e.Conflicts))
	for _, conflict := range e.Conflicts {
		details = append(details, conflict.String())
	}
	return ErrEndpointConflict.Error() + ": " + strings.Join(details, "; ")
}

func (e *EndpointConflictError) Unwrap() error { return ErrEndpointConflict }

// EndpointRegistry is independent of Manager lifecycle. A desktop can share
// one registry across profile managers while each manager owns a unique
// instance scope. Registrations are atomic per scope: a rejected replacement
// leaves the previous registration untouched.
type EndpointRegistry struct {
	mu      sync.RWMutex
	byScope map[string][]EndpointRecord
}

func NewEndpointRegistry() *EndpointRegistry {
	return &EndpointRegistry{byScope: make(map[string][]EndpointRecord)}
}

func (r *EndpointRegistry) ReplaceScope(scope string, records []EndpointRecord) error {
	scope = strings.TrimSpace(scope)
	if r == nil {
		return nil
	}
	if scope == "" {
		return errors.New("endpoint registry scope is required")
	}
	if r.byScope == nil {
		r.byScope = make(map[string][]EndpointRecord)
	}
	normalized := make([]EndpointRecord, 0, len(records))
	seen := make(map[string]EndpointRecord, len(records))
	for _, record := range records {
		record = normalizeEndpointRecord(record, scope)
		if err := validateEndpointRecord(record); err != nil {
			return err
		}
		key := endpointKey(record)
		if previous, exists := seen[key]; exists {
			return &EndpointConflictError{Conflicts: []EndpointConflict{{Existing: previous, Candidate: record}}}
		}
		seen[key] = record
		normalized = append(normalized, record)
	}
	sortEndpointRecords(normalized)
	r.mu.Lock()
	defer r.mu.Unlock()
	var conflicts []EndpointConflict
	for existingScope, existingRecords := range r.byScope {
		if existingScope == scope {
			continue
		}
		for _, existing := range existingRecords {
			for _, candidate := range normalized {
				if endpointRecordsConflict(existing, candidate) {
					conflicts = append(conflicts, EndpointConflict{Existing: existing, Candidate: candidate})
				}
			}
		}
	}
	if len(conflicts) > 0 {
		sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].String() < conflicts[j].String() })
		return &EndpointConflictError{Conflicts: conflicts}
	}
	if len(normalized) == 0 {
		delete(r.byScope, scope)
	} else {
		r.byScope[scope] = normalized
	}
	return nil
}

func (r *EndpointRegistry) MarkScopeRunning(scope string, generation uint64) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	records, ok := r.byScope[scope]
	if !ok {
		return false
	}
	for index := range records {
		if records[index].Owner.InstanceGeneration != generation {
			return false
		}
	}
	for index := range records {
		records[index].State = EndpointStateRunning
	}
	return true
}

func (r *EndpointRegistry) RemoveScope(scope string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.byScope, scope)
	r.mu.Unlock()
}

func (r *EndpointRegistry) Snapshot() []EndpointRecord {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	var records []EndpointRecord
	for _, scoped := range r.byScope {
		records = append(records, scoped...)
	}
	r.mu.RUnlock()
	sortEndpointRecords(records)
	return records
}

func (r *EndpointRegistry) SnapshotForProfile(profileID string) []EndpointRecord {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return nil
	}
	var records []EndpointRecord
	for _, record := range r.Snapshot() {
		if record.Owner.ProfileID == profileID {
			records = append(records, record)
		}
	}
	return records
}

func (r *EndpointRegistry) Conflicts(records []EndpointRecord) []EndpointConflict {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var conflicts []EndpointConflict
	for _, scoped := range r.byScope {
		for _, existing := range scoped {
			for _, candidate := range records {
				candidate = normalizeEndpointRecord(candidate, candidate.Owner.InstanceScope)
				if validateEndpointRecord(candidate) == nil && endpointRecordsConflict(existing, candidate) {
					conflicts = append(conflicts, EndpointConflict{Existing: existing, Candidate: candidate})
				}
			}
		}
	}
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].String() < conflicts[j].String() })
	return conflicts
}

func (r *EndpointRegistry) Reservations() []TargetReservation {
	return endpointReservations(r.Snapshot())
}

func (r *EndpointRegistry) Diagnostics() []string {
	records := r.Snapshot()
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, fmt.Sprintf("%s/%s %s:%d state=%s owner=%s generation=%d rule=%s visitor=%s",
			record.Kind, record.Protocol, record.Host, record.Port, record.State,
			record.Owner.ProfileID, record.Owner.InstanceGeneration, record.Owner.RuleID, record.Owner.VisitorID))
	}
	return out
}

func endpointReservations(records []EndpointRecord) []TargetReservation {
	out := make([]TargetReservation, 0, len(records))
	for _, record := range records {
		purpose := record.Owner.Purpose
		if purpose == "" {
			purpose = string(record.Kind) + " listener"
		}
		out = append(out, TargetReservation{
			Host: record.Host, Port: record.Port, Purpose: purpose,
			AllowVisitorBind: record.Kind == EndpointKindVisitor,
			OwnerProfileID:   record.Owner.ProfileID,
			VisitorID:        record.Owner.VisitorID,
		})
	}
	return out
}

func normalizeEndpointRecord(record EndpointRecord, scope string) EndpointRecord {
	record.Host = strings.TrimSpace(record.Host)
	record.Protocol = EndpointProtocol(strings.ToLower(strings.TrimSpace(string(record.Protocol))))
	record.Kind = EndpointKind(strings.ToLower(strings.TrimSpace(string(record.Kind))))
	record.State = EndpointState(strings.ToLower(strings.TrimSpace(string(record.State))))
	if record.State == "" {
		record.State = EndpointStateStarting
	}
	record.Owner.ProfileID = strings.TrimSpace(record.Owner.ProfileID)
	record.Owner.InstanceScope = strings.TrimSpace(scope)
	record.Owner.RuleID = strings.TrimSpace(record.Owner.RuleID)
	record.Owner.VisitorID = strings.TrimSpace(record.Owner.VisitorID)
	record.Owner.Purpose = strings.TrimSpace(record.Owner.Purpose)
	return record
}

func validateEndpointRecord(record EndpointRecord) error {
	addr, err := netip.ParseAddr(record.Host)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("endpoint listener host must be a literal IPv4 address: %q", record.Host)
	}
	if record.Port < 1 || record.Port > 65535 {
		return fmt.Errorf("endpoint listener port is invalid: %d", record.Port)
	}
	if record.Protocol != EndpointProtocolTCP && record.Protocol != EndpointProtocolUDP {
		return fmt.Errorf("endpoint listener protocol is invalid: %q", record.Protocol)
	}
	switch record.Kind {
	case EndpointKindAdmin, EndpointKindVisitor, EndpointKindTargetGateway, EndpointKindEgressProxy:
	default:
		return fmt.Errorf("endpoint listener kind is invalid: %q", record.Kind)
	}
	if record.State != EndpointStateStarting && record.State != EndpointStateRunning {
		return fmt.Errorf("endpoint listener state is invalid: %q", record.State)
	}
	return nil
}

func endpointKey(record EndpointRecord) string {
	return fmt.Sprintf("%s/%s/%d", record.Protocol, record.Host, record.Port)
}

func endpointRecordsConflict(left, right EndpointRecord) bool {
	if left.Protocol != right.Protocol || left.Port != right.Port {
		return false
	}
	leftAddr, leftErr := netip.ParseAddr(left.Host)
	rightAddr, rightErr := netip.ParseAddr(right.Host)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return leftAddr == rightAddr || leftAddr.IsUnspecified() || rightAddr.IsUnspecified()
}

func sortEndpointRecords(records []EndpointRecord) {
	sort.Slice(records, func(i, j int) bool {
		left, right := records[i], records[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Owner.InstanceScope < right.Owner.InstanceScope
	})
}
