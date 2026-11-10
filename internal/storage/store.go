package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/private-radminlan/lanmesh/core"
)

var ErrNotFound = errors.New("not found")
var ErrInvalidPassword = errors.New("invalid network password")
var ErrNetworkFull = errors.New("network address pool is full")
var ErrConflict = errors.New("resource conflict")
var ErrBlocked = errors.New("device is blocked")

type State struct {
	PrivateNetworkID  string                        `json:"private_network_id,omitempty"`
	EnrollmentKey     string                        `json:"enrollment_key,omitempty"`
	MemberCredentials map[string]MemberCredential   `json:"member_credentials,omitempty"`
	Networks          map[string]Network            `json:"networks"`
	Devices           map[string]RegisteredDevice   `json:"devices,omitempty"`
	Candidates        map[string]CandidateRecord    `json:"candidates,omitempty"`
	Diagnostics       map[string][]DiagnosticReport `json:"diagnostics,omitempty"`
}
type Network struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	CIDR         string            `json:"cidr"`
	PasswordHash string            `json:"password_hash"`
	CreatedAt    time.Time         `json:"created_at"`
	Devices      map[string]Device `json:"devices"`
}
type Device struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key,omitempty"`
	VirtualIP  string    `json:"virtual_ip"`
	JoinedAt   time.Time `json:"joined_at"`
	LastSeen   time.Time `json:"last_seen"`
	Online     bool      `json:"online"`
	Blocked    bool      `json:"blocked,omitempty"`
	Forwarding *bool     `json:"forwarding,omitempty"`
}

// RegisteredDevice is the control-plane identity. Network membership remains
// represented by Device for compatibility with the original state format.
type RegisteredDevice struct {
	Identity    core.DeviceIdentity `json:"identity"`
	DisplayName string              `json:"display_name,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	LastSeen    time.Time           `json:"last_seen"`
	Online      bool                `json:"online"`
	Blocked     bool                `json:"blocked,omitempty"`
}

type CandidateRecord struct {
	DeviceID   core.DeviceID    `json:"device_id"`
	NetworkID  core.NetworkID   `json:"network_id"`
	Candidates []core.Candidate `json:"candidates"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

type DiagnosticCheck struct {
	Name    string    `json:"name"`
	Status  string    `json:"status"`
	Detail  string    `json:"detail,omitempty"`
	Checked time.Time `json:"checked"`
}

type DiagnosticReport struct {
	DeviceID  core.DeviceID     `json:"device_id"`
	NetworkID core.NetworkID    `json:"network_id"`
	Checks    []DiagnosticCheck `json:"checks"`
	FRPReport json.RawMessage   `json:"frp_report,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}
type NetworkSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	CreatedAt time.Time `json:"created_at"`
	Devices   int       `json:"devices"`
}

type Store struct {
	mu        sync.RWMutex
	path      string
	data      State
	committed []byte
}

func (s *Store) CreateNetwork(name, password, cidr string) (NetworkSummary, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.TrimSpace(password) == "" || len(name) > 128 {
		return NetworkSummary{}, errors.New("name and password are required")
	}
	if len([]byte(password)) < 8 {
		return NetworkSummary{}, errors.New("network password must be at least 8 characters")
	}
	if cidr == "" {
		cidr = "10.240.0.0/24"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return NetworkSummary{}, errors.New("invalid IPv4 cidr")
	}
	prefix = prefix.Masked()
	if !isPrivatePool(prefix) {
		return NetworkSummary{}, errors.New("cidr must be an IPv4 private pool in 10.0.0.0/8 or 100.64.0.0/10")
	}
	network := Network{ID: newID("net"), Name: name, CIDR: prefix.String(), PasswordHash: hashPassword(password), CreatedAt: time.Now().UTC(), Devices: map[string]Device{}}
	s.mu.Lock()
	s.data.Networks[network.ID] = network
	err = s.persistLocked()
	summary := summarize(network)
	s.mu.Unlock()
	if err != nil {
		return NetworkSummary{}, err
	}
	return summary, nil
}

func (s *Store) ListNetworks() []NetworkSummary {
	s.mu.RLock()
	items := make([]NetworkSummary, 0, len(s.data.Networks))
	for _, network := range s.data.Networks {
		items = append(items, summarize(network))
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items
}

func (s *Store) JoinNetwork(networkID, name, publicKey, password string) (Device, error) {
	if len(name) > 128 {
		return Device{}, errors.New("device name exceeds 128 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		return Device{}, ErrNotFound
	}
	if !verifyPassword(password, network.PasswordHash) {
		return Device{}, ErrInvalidPassword
	}
	for _, existing := range network.Devices {
		if publicKey != "" && existing.PublicKey == publicKey {
			existing.LastSeen = time.Now().UTC()
			existing.Online = true
			network.Devices[existing.ID] = existing
			if err := s.persistLocked(); err != nil {
				return Device{}, err
			}
			return cloneDevice(existing), nil
		}
	}
	if len(network.Devices) >= 128 {
		return Device{}, ErrNetworkFull
	}
	virtualIP, err := nextIP(network)
	if err != nil {
		return Device{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = "Unnamed device"
	}
	now := time.Now().UTC()
	device := Device{ID: newID("dev"), Name: strings.TrimSpace(name), PublicKey: strings.TrimSpace(publicKey), VirtualIP: virtualIP, JoinedAt: now, LastSeen: now, Online: true}
	network.Devices[device.ID] = device
	s.data.Networks[networkID] = network
	if err := s.persistLocked(); err != nil {
		return Device{}, err
	}
	return cloneDevice(device), nil
}

// JoinRegisteredNetwork attaches an already registered identity to a network
// while preserving its stable device ID. This is the phase-5 path used by
// candidate, diagnostics, and relay authorization.
func (s *Store) JoinRegisteredNetwork(networkID core.NetworkID, name, password string, deviceID core.DeviceID) (Device, error) {
	if len(name) > 128 {
		return Device{}, errors.New("device name exceeds 128 bytes")
	}
	if err := networkID.Validate(); err != nil {
		return Device{}, err
	}
	if err := deviceID.Validate(); err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registered, ok := s.data.Devices[deviceID.String()]
	if !ok {
		return Device{}, ErrNotFound
	}
	network, ok := s.data.Networks[networkID.String()]
	if !ok {
		return Device{}, ErrNotFound
	}
	if !verifyPassword(password, network.PasswordHash) {
		return Device{}, ErrInvalidPassword
	}
	for existingID, existing := range network.Devices {
		if existingID != deviceID.String() && existing.PublicKey != "" && existing.PublicKey == registered.Identity.WireGuardPublicKey {
			return Device{}, ErrConflict
		}
	}
	if existing, ok := network.Devices[deviceID.String()]; ok {
		existing.LastSeen = time.Now().UTC()
		existing.Online = true
		network.Devices[deviceID.String()] = existing
		if err := s.persistLocked(); err != nil {
			return Device{}, err
		}
		return cloneDevice(existing), nil
	}
	if len(network.Devices) >= 128 {
		return Device{}, ErrNetworkFull
	}
	virtualIP, err := nextIP(network)
	if err != nil {
		return Device{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = registered.DisplayName
	}
	if strings.TrimSpace(name) == "" {
		name = "Unnamed device"
	}
	now := time.Now().UTC()
	device := Device{ID: deviceID.String(), Name: strings.TrimSpace(name), PublicKey: registered.Identity.WireGuardPublicKey, VirtualIP: virtualIP, JoinedAt: now, LastSeen: now, Online: true}
	network.Devices[device.ID] = device
	s.data.Networks[networkID.String()] = network
	if err := s.persistLocked(); err != nil {
		return Device{}, err
	}
	return cloneDevice(device), nil
}

func (s *Store) NetworkMembershipExists(networkID core.NetworkID, deviceID core.DeviceID) bool {
	if networkID.Validate() != nil || deviceID.Validate() != nil {
		return false
	}
	s.mu.RLock()
	network, ok := s.data.Networks[networkID.String()]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	member, ok := network.Devices[deviceID.String()]
	if !ok || member.Blocked {
		s.mu.RUnlock()
		return false
	}
	s.mu.RUnlock()
	return true
}

func (s *Store) PrivateNetwork() (NetworkSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	network, ok := s.data.Networks[s.data.PrivateNetworkID]
	if !ok {
		return NetworkSummary{}, ErrNotFound
	}
	return summarize(network), nil
}

func (s *Store) ListDevices(networkID string) ([]Device, error) {
	return s.ListDevicesWithBlocked(networkID, false)
}

func (s *Store) ListDevicesWithBlocked(networkID string, includeBlocked bool) ([]Device, error) {
	s.mu.RLock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	items := make([]Device, 0, len(network.Devices))
	for _, device := range network.Devices {
		if device.Blocked && !includeBlocked {
			continue
		}
		device.Online = !device.Blocked && time.Since(device.LastSeen) < 30*time.Second && (device.Forwarding == nil || *device.Forwarding)
		items = append(items, cloneDevice(device))
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].JoinedAt.Before(items[j].JoinedAt) })
	return items, nil
}

func validateMemberName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]byte(name)) > 128 || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("member name must contain 1-128 non-control characters")
	}
	return name, nil
}

func (s *Store) RenameDevice(networkID, deviceID, name string) (Device, error) {
	name, err := validateMemberName(name)
	if err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		return Device{}, ErrNotFound
	}
	member, ok := network.Devices[deviceID]
	if !ok {
		return Device{}, ErrNotFound
	}
	member.Name = name
	network.Devices[deviceID] = member
	s.data.Networks[networkID] = network
	if registered, ok := s.data.Devices[deviceID]; ok {
		registered.DisplayName = name
		s.data.Devices[deviceID] = registered
	}
	if err := s.persistLocked(); err != nil {
		return Device{}, err
	}
	return cloneDevice(member), nil
}

func (s *Store) SetDeviceBlocked(networkID, deviceID string, blocked bool) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		return Device{}, ErrNotFound
	}
	member, ok := network.Devices[deviceID]
	if !ok {
		return Device{}, ErrNotFound
	}
	member.Blocked = blocked
	if blocked {
		member.Online = false
		for hash, credential := range s.data.MemberCredentials {
			if credential.NetworkID == networkID && credential.DeviceID == deviceID {
				delete(s.data.MemberCredentials, hash)
			}
		}
	}
	network.Devices[deviceID] = member
	s.data.Networks[networkID] = network
	if registered, ok := s.data.Devices[deviceID]; ok {
		registered.Blocked = blocked
		if blocked {
			registered.Online = false
		}
		s.data.Devices[deviceID] = registered
	}
	if err := s.persistLocked(); err != nil {
		return Device{}, err
	}
	return cloneDevice(member), nil
}

func (s *Store) RevokeMemberCredentials(networkID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := network.Devices[deviceID]; !ok {
		return ErrNotFound
	}
	for hash, credential := range s.data.MemberCredentials {
		if credential.NetworkID == networkID && credential.DeviceID == deviceID {
			delete(s.data.MemberCredentials, hash)
		}
	}
	return s.persistLocked()
}

func (s *Store) RemoveDevice(networkID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := network.Devices[deviceID]; !ok {
		return ErrNotFound
	}
	delete(network.Devices, deviceID)
	for hash, credential := range s.data.MemberCredentials {
		if credential.NetworkID == networkID && credential.DeviceID == deviceID {
			delete(s.data.MemberCredentials, hash)
		}
	}
	delete(s.data.Candidates, networkID+"/"+deviceID)
	delete(s.data.Diagnostics, networkID+"/"+deviceID)
	s.data.Networks[networkID] = network
	return s.persistLocked()
}

// RegisterDevice creates or refreshes a control-plane device identity. A
// device ID cannot be rebound to a different public key.
func (s *Store) RegisterDevice(req core.RegisterDeviceRequest) (RegisteredDevice, bool, error) {
	if err := req.Validate(); err != nil {
		return RegisteredDevice{}, false, err
	}
	id := req.DeviceID.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.data.Devices[id]; ok {
		if existing.Identity.WireGuardPublicKey != req.WireGuardPublicKey || existing.Identity.SigningPublicKey != req.SigningPublicKey {
			return RegisteredDevice{}, false, ErrConflict
		}
		existing.DisplayName = strings.TrimSpace(req.DisplayName)
		existing.LastSeen = time.Now().UTC()
		existing.Online = true
		s.data.Devices[id] = existing
		if err := s.persistLocked(); err != nil {
			return RegisteredDevice{}, false, err
		}
		return existing, false, nil
	}
	for existingID, existing := range s.data.Devices {
		if existingID != id && existing.Identity.WireGuardPublicKey == req.WireGuardPublicKey {
			return RegisteredDevice{}, false, ErrConflict
		}
	}
	now := time.Now().UTC()
	device := RegisteredDevice{Identity: core.DeviceIdentity{DeviceID: req.DeviceID, WireGuardPublicKey: req.WireGuardPublicKey, SigningPublicKey: req.SigningPublicKey}, DisplayName: strings.TrimSpace(req.DisplayName), CreatedAt: now, LastSeen: now, Online: true}
	s.data.Devices[id] = device
	if err := s.persistLocked(); err != nil {
		return RegisteredDevice{}, false, err
	}
	return device, true, nil
}

func (s *Store) Heartbeat(deviceID core.DeviceID) (RegisteredDevice, error) {
	if err := deviceID.Validate(); err != nil {
		return RegisteredDevice{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.data.Devices[deviceID.String()]
	if !ok {
		return RegisteredDevice{}, ErrNotFound
	}
	if device.Blocked {
		return RegisteredDevice{}, ErrBlocked
	}
	for _, network := range s.data.Networks {
		if member, ok := network.Devices[deviceID.String()]; ok && member.Blocked {
			return RegisteredDevice{}, ErrBlocked
		}
	}
	device.LastSeen = time.Now().UTC()
	device.Online = true
	s.data.Devices[deviceID.String()] = device
	for id, network := range s.data.Networks {
		if member, ok := network.Devices[deviceID.String()]; ok {
			member.LastSeen = device.LastSeen
			member.Online = true
			network.Devices[member.ID] = member
			s.data.Networks[id] = network
		}
	}
	if err := s.persistLocked(); err != nil {
		return RegisteredDevice{}, err
	}
	return device, nil
}

// RegisteredDeviceExists reports whether an identity has completed the
// control-plane registration flow. It is used before issuing relay tickets so
// arbitrary strings cannot consume relay capacity.
func (s *Store) RegisteredDeviceExists(deviceID core.DeviceID) bool {
	if deviceID.Validate() != nil {
		return false
	}
	s.mu.RLock()
	device, ok := s.data.Devices[deviceID.String()]
	if !ok || device.Blocked {
		s.mu.RUnlock()
		return false
	}
	s.mu.RUnlock()
	return true
}

func candidateKey(networkID core.NetworkID, deviceID core.DeviceID) string {
	return networkID.String() + "/" + deviceID.String()
}

func (s *Store) SetCandidates(networkID core.NetworkID, deviceID core.DeviceID, candidates []core.Candidate) (CandidateRecord, error) {
	if err := networkID.Validate(); err != nil {
		return CandidateRecord{}, err
	}
	if err := deviceID.Validate(); err != nil {
		return CandidateRecord{}, err
	}
	if len(candidates) == 0 || len(candidates) > 64 {
		return CandidateRecord{}, errors.New("between 1 and 64 candidates are required")
	}
	for _, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			return CandidateRecord{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	network, ok := s.data.Networks[networkID.String()]
	if !ok {
		return CandidateRecord{}, ErrNotFound
	}
	if _, ok := s.data.Devices[deviceID.String()]; !ok {
		return CandidateRecord{}, ErrNotFound
	}
	member, ok := network.Devices[deviceID.String()]
	if !ok {
		return CandidateRecord{}, ErrNotFound
	}
	if member.Blocked {
		return CandidateRecord{}, ErrBlocked
	}
	record := CandidateRecord{DeviceID: deviceID, NetworkID: networkID, Candidates: append([]core.Candidate(nil), candidates...), UpdatedAt: time.Now().UTC()}
	s.data.Candidates[candidateKey(networkID, deviceID)] = record
	if err := s.persistLocked(); err != nil {
		return CandidateRecord{}, err
	}
	return cloneCandidates(record), nil
}

func (s *Store) GetCandidates(networkID core.NetworkID, deviceID core.DeviceID) (CandidateRecord, error) {
	if err := networkID.Validate(); err != nil {
		return CandidateRecord{}, err
	}
	if err := deviceID.Validate(); err != nil {
		return CandidateRecord{}, err
	}
	s.mu.RLock()
	network, networkOK := s.data.Networks[networkID.String()]
	record, ok := s.data.Candidates[candidateKey(networkID, deviceID)]
	member, memberOK := network.Devices[deviceID.String()]
	if !networkOK || !memberOK || !ok || member.Blocked {
		s.mu.RUnlock()
		return CandidateRecord{}, ErrNotFound
	}
	record = cloneCandidates(record)
	s.mu.RUnlock()
	return record, nil
}

func summarize(n Network) NetworkSummary {
	return NetworkSummary{ID: n.ID, Name: n.Name, CIDR: n.CIDR, CreatedAt: n.CreatedAt, Devices: len(n.Devices)}
}

func nextIP(network Network) (string, error) {
	_, block, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return "", err
	}
	base := block.IP.To4()
	if base == nil {
		return "", errors.New("only IPv4 networks are supported")
	}
	used := map[string]bool{}
	for _, d := range network.Devices {
		used[d.VirtualIP] = true
	}
	for candidate := append(net.IP(nil), base...); ; increment(candidate) {
		if !block.Contains(candidate) {
			break
		}
		if candidate.Equal(base) || candidate.Equal(lastIP(block)) {
			continue
		}
		ip := candidate.String()
		if !used[ip] {
			return ip, nil
		}
	}
	return "", ErrNetworkFull
}

func isPrivatePool(prefix netip.Prefix) bool {
	b := prefix.Addr().As4()
	if b[0] == 10 {
		return prefix.Bits() >= 8
	}
	return b[0] == 100 && b[1] >= 64 && b[1] <= 127 && prefix.Bits() >= 10
}
func lastIP(block *net.IPNet) net.IP {
	last := append(net.IP(nil), block.IP.To4()...)
	for i := range last {
		last[i] |= ^block.Mask[i]
	}
	return last
}
func increment(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b)
}
