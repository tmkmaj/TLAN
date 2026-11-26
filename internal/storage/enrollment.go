package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

type MemberCredential struct {
	NetworkID string `json:"network_id"`
	DeviceID  string `json:"device_id"`
}

// EnsurePrivateNetwork is an administrator startup operation. It preserves
// member addresses when the server restarts or its shared join code changes.
func (s *Store) EnsurePrivateNetwork(name, code, cidr string) (NetworkSummary, error) {
	if len(code) < 8 || len(code) > 256 {
		return NetworkSummary{}, errors.New("join code must be 8-256 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.data.PrivateNetworkID
	if id == "" {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 128 {
			return NetworkSummary{}, errors.New("invalid network name")
		}
		if cidr == "" {
			cidr = "10.240.0.0/24"
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 || !isPrivatePool(prefix.Masked()) {
			return NetworkSummary{}, errors.New("invalid IPv4 cidr")
		}
		id = newID("net")
		s.data.Networks[id] = Network{ID: id, Name: name, CIDR: prefix.Masked().String(), PasswordHash: hashPassword(code), CreatedAt: time.Now().UTC(), Devices: make(map[string]Device)}
	}
	n, ok := s.data.Networks[id]
	if !ok {
		return NetworkSummary{}, ErrNotFound
	}
	if !verifyPassword(code, n.PasswordHash) {
		n.PasswordHash = hashPassword(code)
	}
	s.data.Networks[id] = n
	s.data.PrivateNetworkID = id
	if err := s.persistLocked(); err != nil {
		return NetworkSummary{}, err
	}
	return summarize(n), nil
}

// EnrollPrivate issues a token scoped to one device in one network. The HTTP
// layer seals that token to the device's X25519 key before returning it.
func (s *Store) EnrollPrivate(req core.RegisterDeviceRequest, code string) (NetworkSummary, Device, string, error) {
	return s.enrollPrivate(req, code, false)
}

// EnrollPrivateAsAdmin joins the private network without consuming the normal
// network join code. The caller must authenticate the configured admin token
// before calling this method.
func (s *Store) EnrollPrivateAsAdmin(req core.RegisterDeviceRequest) (NetworkSummary, Device, string, error) {
	return s.enrollPrivate(req, "", true)
}

func (s *Store) enrollPrivate(req core.RegisterDeviceRequest, code string, admin bool) (NetworkSummary, Device, string, error) {
	if err := req.Validate(); err != nil {
		return NetworkSummary{}, Device{}, "", err
	}
	if !admin && len(code) > 256 {
		return NetworkSummary{}, Device{}, "", ErrInvalidPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Networks[s.data.PrivateNetworkID]
	if !ok {
		return NetworkSummary{}, Device{}, "", errors.New("private enrollment is disabled")
	}
	if !admin && !verifyPassword(code, n.PasswordHash) {
		return NetworkSummary{}, Device{}, "", ErrInvalidPassword
	}
	id := req.DeviceID.String()
	if registered, ok := s.data.Devices[id]; ok && registered.Blocked {
		return NetworkSummary{}, Device{}, "", ErrBlocked
	}
	if member, ok := n.Devices[id]; ok && member.Blocked {
		return NetworkSummary{}, Device{}, "", ErrBlocked
	}
	if existing, ok := s.data.Devices[id]; ok && existing.Identity.WireGuardPublicKey != req.WireGuardPublicKey {
		return NetworkSummary{}, Device{}, "", ErrConflict
	}
	for other, d := range s.data.Devices {
		if other != id && d.Identity.WireGuardPublicKey == req.WireGuardPublicKey {
			return NetworkSummary{}, Device{}, "", ErrConflict
		}
	}
	member, exists := n.Devices[id]
	now := time.Now().UTC()
	customName := strings.TrimSpace(req.DisplayName)
	if !exists {
		if len(n.Devices) >= 128 {
			return NetworkSummary{}, Device{}, "", ErrNetworkFull
		}
		ip, err := nextIP(n)
		if err != nil {
			return NetworkSummary{}, Device{}, "", err
		}
		off := false
		member = Device{ID: id, Name: customName, PublicKey: req.WireGuardPublicKey, VirtualIP: ip, JoinedAt: now, LastSeen: now, Forwarding: &off}
		if member.Name == "" {
			member.Name = "TLAN Device"
		}
	} else if customName != "" {
		if validName, err := validateMemberName(customName); err == nil {
			member.Name = validName
		}
	}
	if s.data.EnrollmentKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return NetworkSummary{}, Device{}, "", err
		}
		s.data.EnrollmentKey = base64.RawStdEncoding.EncodeToString(key)
	}
	key, err := base64.RawStdEncoding.DecodeString(s.data.EnrollmentKey)
	if err != nil || len(key) != 32 {
		return NetworkSummary{}, Device{}, "", errors.New("invalid enrollment signing key")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("LANMesh member v1\x00" + n.ID + "\x00" + id + "\x00" + req.WireGuardPublicKey + "\x00" + member.JoinedAt.Format(time.RFC3339Nano)))
	token := "member_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if s.data.MemberCredentials == nil {
		s.data.MemberCredentials = make(map[string]MemberCredential)
	}
	s.data.MemberCredentials[credentialHash(token)] = MemberCredential{NetworkID: n.ID, DeviceID: id}
	registered, exists := s.data.Devices[id]
	if !exists {
		registered = RegisteredDevice{Identity: core.DeviceIdentity{DeviceID: req.DeviceID, WireGuardPublicKey: req.WireGuardPublicKey}, CreatedAt: now}
	}
	registered.DisplayName = member.Name
	s.data.Devices[id] = registered
	n.Devices[id] = member
	s.data.Networks[n.ID] = n
	if err := s.persistLocked(); err != nil {
		return NetworkSummary{}, Device{}, "", err
	}
	return summarize(n), cloneDevice(member), token, nil
}
func credentialHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *Store) AuthenticateMember(token string) (MemberCredential, bool) {
	if !strings.HasPrefix(token, "member_") || len(token) > 128 {
		return MemberCredential{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.data.MemberCredentials[credentialHash(token)]
	if !ok {
		return c, false
	}
	n, ok := s.data.Networks[c.NetworkID]
	if !ok {
		return c, false
	}
	member, ok := n.Devices[c.DeviceID]
	if !ok || member.Blocked {
		return c, false
	}
	if registered, ok := s.data.Devices[c.DeviceID]; ok && registered.Blocked {
		return c, false
	}
	return c, ok
}
func (s *Store) NetworkSummary(id string) (NetworkSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.data.Networks[id]
	if !ok {
		return NetworkSummary{}, ErrNotFound
	}
	return summarize(n), nil
}
func (s *Store) SetForwarding(nid, did string, enabled bool) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.data.Networks[nid]
	if !ok {
		return Device{}, ErrNotFound
	}
	m, ok := n.Devices[did]
	if !ok {
		return Device{}, ErrNotFound
	}
	m.Forwarding = &enabled
	m.Online = enabled
	m.LastSeen = time.Now().UTC()
	n.Devices[did] = m
	s.data.Networks[nid] = n
	if err := s.persistLocked(); err != nil {
		return Device{}, err
	}
	return cloneDevice(m), nil
}
