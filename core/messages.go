package core

import (
	"errors"
	"strings"
	"time"
)

// RegisterDeviceRequest is sent over the authenticated control connection.
// Device private keys are never part of this request.
type RegisterDeviceRequest struct {
	DeviceID           DeviceID `json:"device_id"`
	WireGuardPublicKey string   `json:"wireguard_public_key"`
	SigningPublicKey   string   `json:"signing_public_key,omitempty"`
	DisplayName        string   `json:"display_name,omitempty"`
}

func (r RegisterDeviceRequest) Validate() error {
	identity := DeviceIdentity{DeviceID: r.DeviceID, WireGuardPublicKey: r.WireGuardPublicKey, SigningPublicKey: r.SigningPublicKey}
	if err := identity.Validate(); err != nil {
		return err
	}
	if len(r.DisplayName) > 128 {
		return errors.New("display name is too long")
	}
	return nil
}

type RegisterDeviceResponse struct {
	Identity  DeviceIdentity `json:"identity"`
	CreatedAt time.Time      `json:"created_at"`
}

type JoinNetworkRequest struct {
	NetworkID   NetworkID `json:"network_id"`
	DeviceID    DeviceID  `json:"device_id"`
	Password    string    `json:"password"`
	InviteToken string    `json:"invite_token,omitempty"`
}

func (r JoinNetworkRequest) Validate() error {
	if err := r.NetworkID.Validate(); err != nil {
		return err
	}
	if err := r.DeviceID.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.Password) == "" && strings.TrimSpace(r.InviteToken) == "" {
		return errors.New("password or invite token is required")
	}
	return nil
}

type JoinNetworkResponse struct {
	Member    NetworkMember   `json:"member"`
	Peers     []NetworkMember `json:"peers"`
	ExpiresAt time.Time       `json:"expires_at,omitempty"`
}

type SignalOffer struct {
	SessionID  string      `json:"session_id"`
	From       DeviceID    `json:"from"`
	To         DeviceID    `json:"to"`
	Candidates []Candidate `json:"candidates"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
}

func (o SignalOffer) Validate(now time.Time) error {
	if o.SessionID == "" || len(o.SessionID) > 128 {
		return errors.New("signal session ID is required")
	}
	if err := o.From.Validate(); err != nil {
		return err
	}
	if err := o.To.Validate(); err != nil {
		return err
	}
	if o.From == o.To {
		return errors.New("signal endpoints must differ")
	}
	if len(o.Candidates) == 0 {
		return errors.New("signal offer requires candidates")
	}
	for _, candidate := range o.Candidates {
		if err := candidate.Validate(); err != nil {
			return err
		}
	}
	if !o.ExpiresAt.After(now) {
		return errors.New("signal offer is expired")
	}
	return nil
}

type PeerSnapshot struct {
	NetworkID NetworkID       `json:"network_id"`
	Members   []NetworkMember `json:"members"`
	Revision  uint64          `json:"revision"`
	UpdatedAt time.Time       `json:"updated_at"`
}
