// Package egress owns the application egress profile model, strict persistence,
// authenticated frame protocol, and transport-agnostic client session.
package egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	// SchemaVersion is the on-disk profile document schema.
	SchemaVersion = 1
	// SecretSchemaVersion is the on-disk protected-secret document schema.
	SecretSchemaVersion = 1
	// MaxProfiles bounds one profile document.
	MaxProfiles = 128
	// MaxRules bounds rules in one profile.
	MaxRules = 64
	// MaxConfigBytes bounds JSON documents read from disk or the wire.
	MaxConfigBytes = 1 << 20
	// MaxSecretBytes bounds one secret value before DPAPI protection.
	MaxSecretBytes = 8 * 1024
	// MaxTargetAllowList bounds one policy allow list.
	MaxTargetAllowList = 128
	// MaxNameLength bounds identifiers and display names.
	MaxNameLength = 128
)

const (
	CodeInvalidProfile         = "EGRESS_INVALID_PROFILE"
	CodeInvalidConfig          = "EGRESS_INVALID_CONFIG"
	CodeInvalidRule            = "EGRESS_INVALID_RULE"
	CodeUnsupported            = "EGRESS_UNSUPPORTED"
	CodeStore                  = "EGRESS_STORE"
	CodeProfileNotFound        = "EGRESS_PROFILE_NOT_FOUND"
	CodeDuplicateProfile       = "EGRESS_DUPLICATE_PROFILE"
	CodeInvalidID              = "EGRESS_INVALID_ID"
	CodeSecretNotFound         = "EGRESS_SECRET_NOT_FOUND"
	CodeInvalidSessionConfig   = "EGRESS_INVALID_SESSION_CONFIG"
	CodeAlreadyRunning         = "EGRESS_ALREADY_RUNNING"
	CodeSessionClosed          = "EGRESS_SESSION_CLOSED"
	CodeInvalidFrame           = "EGRESS_INVALID_FRAME"
	CodeUnknownFrameType       = "EGRESS_UNKNOWN_FRAME_TYPE"
	CodeFrameTooLarge          = "EGRESS_FRAME_TOO_LARGE"
	CodeFrameRateLimited       = "EGRESS_FRAME_RATE_LIMITED"
	CodeInvalidFramePayload    = "EGRESS_INVALID_FRAME_PAYLOAD"
	CodeAuthentication         = "EGRESS_AUTHENTICATION"
	CodeReplay                 = "EGRESS_REPLAY"
	CodeSessionMismatch        = "EGRESS_SESSION_MISMATCH"
	CodeHandshakeRejected      = "EGRESS_HANDSHAKE_REJECTED"
	CodePeerTimeout            = "EGRESS_PEER_TIMEOUT"
	CodeRemoteError            = "EGRESS_REMOTE_ERROR"
	CodeStreamClosed           = "EGRESS_STREAM_CLOSED"
	CodeDuplicateStream        = "EGRESS_DUPLICATE_STREAM"
	CodeUnknownStream          = "EGRESS_UNKNOWN_STREAM"
	CodeStreamBufferFull       = "EGRESS_STREAM_BUFFER_FULL"
	CodeInvalidStateTransition = "EGRESS_INVALID_STATE_TRANSITION"
	CodeSequenceExhausted      = "EGRESS_SEQUENCE_EXHAUSTED"
)

var (
	ErrInvalidProfile         = errors.New("invalid egress profile")
	ErrInvalidRule            = errors.New("invalid egress rule")
	ErrUnsupported            = errors.New("unsupported egress feature")
	ErrInvalidConfig          = errors.New("invalid egress configuration")
	ErrDuplicateProfile       = errors.New("duplicate egress profile")
	ErrProfileNotFound        = errors.New("egress profile not found")
	ErrSecretNotFound         = errors.New("egress secret not found")
	ErrInvalidID              = errors.New("invalid egress identifier")
	ErrInvalidSessionConfig   = errors.New("invalid egress session configuration")
	ErrAlreadyRunning         = errors.New("egress session is already running")
	ErrSessionClosed          = errors.New("egress session is closed")
	ErrStreamClosed           = errors.New("egress stream is closed")
	ErrDuplicateStream        = errors.New("egress stream already exists")
	ErrUnknownStream          = errors.New("unknown egress stream")
	ErrStreamBufferFull       = errors.New("egress stream receive buffer is full")
	ErrInvalidStateTransition = errors.New("invalid egress state transition")
	ErrInvalidFrame           = errors.New("invalid egress frame")
	ErrUnknownFrameType       = errors.New("unknown egress frame type")
	ErrFrameTooLarge          = errors.New("egress frame payload is too large")
	ErrFrameRateLimited       = errors.New("egress frame rate limit exceeded")
	ErrInvalidFramePayload    = errors.New("invalid egress frame payload")
	ErrAuthentication         = errors.New("egress frame authentication failed")
	ErrReplay                 = errors.New("egress frame replay detected")
	ErrSessionMismatch        = errors.New("egress frame session does not match")
	ErrHandshakeRejected      = errors.New("egress handshake rejected")
	ErrPeerTimeout            = errors.New("egress peer timeout")
	ErrRemoteError            = errors.New("egress peer reported an error")
	ErrSequenceExhausted      = errors.New("egress frame sequence exhausted")
)

// Error carries a stable code while preserving errors.Is behavior for its
// underlying sentinel error.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func codedError(code string, sentinel error, format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return &Error{Code: code, Err: fmt.Errorf("%w: %s", sentinel, detail)}
}

// ErrorCode returns the stable code attached to err, if any.
func ErrorCode(err error) string {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}

// EgressState is the observable lifecycle state of one egress rule/session.
type EgressState string

const (
	StateStopped  EgressState = "stopped"
	StateStarting EgressState = "starting"
	StateRunning  EgressState = "running"
	StateDegraded EgressState = "degraded"
	StateStopping EgressState = "stopping"
	StateError    EgressState = "error"
	StateBlocked  EgressState = "blocked"
)

// Valid reports whether s is one of the seven frozen lifecycle states.
func (s EgressState) Valid() bool {
	switch s {
	case StateStopped, StateStarting, StateRunning, StateDegraded, StateStopping, StateError, StateBlocked:
		return true
	default:
		return false
	}
}

// CanTransitionTo applies the explicit lifecycle transition table.
func (s EgressState) CanTransitionTo(next EgressState) bool {
	switch s {
	case StateStopped:
		return next == StateStarting
	case StateStarting:
		return next == StateRunning || next == StateDegraded || next == StateStopping || next == StateError || next == StateBlocked
	case StateRunning:
		return next == StateDegraded || next == StateStopping || next == StateError || next == StateBlocked
	case StateDegraded:
		return next == StateRunning || next == StateStopping || next == StateError || next == StateBlocked
	case StateStopping:
		return next == StateStopped || next == StateError
	case StateError:
		return next == StateStarting || next == StateStopping || next == StateStopped
	case StateBlocked:
		return next == StateStarting || next == StateStopping || next == StateStopped
	default:
		return false
	}
}

// DesiredState controls only user intent. Loading a profile never starts it.
type DesiredState string

const (
	DesiredStopped DesiredState = "stopped"
	DesiredRunning DesiredState = "running"
)

func (s DesiredState) Valid() bool { return s == DesiredStopped || s == DesiredRunning }

// Protocol is an application transport captured by a rule.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

const (
	IPv6PolicyBlock = "block"
	IPv6PolicyProxy = "proxy"
	DNSPolicyRemote = "remote"
	DNSPolicyLocal  = "local"
	DNSPolicyBlock  = "block"
)

// EgressServer identifies the independent egress gateway endpoint.
type EgressServer struct {
	Endpoint      string `json:"endpoint"`
	Port          int    `json:"port"`
	ServerName    string `json:"serverName,omitempty"`
	TrustedCARef  string `json:"trustedCaRef,omitempty"`
	CredentialRef string `json:"credentialRef"`
}

// EgressPolicy freezes DNS, IPv6, kill-switch, and target allow-list behavior.
// JSON decoding requires killSwitch to be present, even when false.
type EgressPolicy struct {
	IPv6Policy      string   `json:"ipv6Policy"`
	DNSPolicy       string   `json:"dnsPolicy"`
	KillSwitch      bool     `json:"killSwitch"`
	TargetAllowList []string `json:"targetAllowList,omitempty"`

	killSwitchPresent bool
}

// UnmarshalJSON rejects unknown fields and a missing killSwitch setting.
func (p *EgressPolicy) UnmarshalJSON(data []byte) error {
	if p == nil {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "policy destination is nil")
	}
	type wirePolicy struct {
		IPv6Policy      string   `json:"ipv6Policy"`
		DNSPolicy       string   `json:"dnsPolicy"`
		KillSwitch      *bool    `json:"killSwitch"`
		TargetAllowList []string `json:"targetAllowList,omitempty"`
	}
	var wire wirePolicy
	if err := decodeStrictJSON(bytes.NewReader(data), &wire, MaxConfigBytes); err != nil {
		return err
	}
	if wire.KillSwitch == nil {
		return codedError(CodeInvalidProfile, ErrInvalidProfile, "policy.killSwitch is required")
	}
	*p = EgressPolicy{
		IPv6Policy:        wire.IPv6Policy,
		DNSPolicy:         wire.DNSPolicy,
		KillSwitch:        *wire.KillSwitch,
		TargetAllowList:   append([]string(nil), wire.TargetAllowList...),
		killSwitchPresent: true,
	}
	return nil
}

// AppRule selects one normalized executable path and its protocols.
type AppRule struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	ExePath         string     `json:"exePath"`
	IncludeChildren bool       `json:"includeChildren"`
	Enabled         bool       `json:"enabled"`
	Protocols       []Protocol `json:"protocols"`
}

// EgressProfile is one independent egress configuration revision.
type EgressProfile struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Version      uint64       `json:"version"`
	Server       EgressServer `json:"server"`
	Policy       EgressPolicy `json:"policy"`
	Rules        []AppRule    `json:"rules"`
	DesiredState DesiredState `json:"desiredState"`
}

// ProfilesDocument is the profiles.json root object.
type ProfilesDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	Profiles      []EgressProfile `json:"profiles"`
}

// RuleState is the per-rule portion of an EgressSnapshot.
type RuleState struct {
	RuleID    string      `json:"ruleId"`
	State     EgressState `json:"state"`
	LastError string      `json:"lastError,omitempty"`
}

// EgressSnapshot is the immutable observable session state returned to callers.
type EgressSnapshot struct {
	State           EgressState `json:"state"`
	RuleStates      []RuleState `json:"ruleStates"`
	BytesSent       uint64      `json:"bytesSent"`
	BytesReceived   uint64      `json:"bytesReceived"`
	PacketsSent     uint64      `json:"packetsSent"`
	PacketsReceived uint64      `json:"packetsReceived"`
	LastError       string      `json:"lastError,omitempty"`
	StartedAt       time.Time   `json:"startedAt"`
	UpdatedAt       time.Time   `json:"updatedAt"`
	StoppedAt       time.Time   `json:"stoppedAt,omitempty"`
}

// DecodeProfiles strictly decodes and validates a profile document. It never
// starts a profile, regardless of desiredState.
func DecodeProfiles(r io.Reader) (ProfilesDocument, error) {
	var doc ProfilesDocument
	if err := decodeStrictJSON(r, &doc, MaxConfigBytes); err != nil {
		return ProfilesDocument{}, err
	}
	if doc.SchemaVersion != SchemaVersion {
		return ProfilesDocument{}, codedError(CodeInvalidProfile, ErrInvalidProfile, "schemaVersion must be %d", SchemaVersion)
	}
	if err := ValidateProfilesDocument(doc); err != nil {
		return ProfilesDocument{}, err
	}
	return doc, nil
}

// EncodeProfiles validates and encodes a profile document deterministically.
func EncodeProfiles(doc ProfilesDocument) ([]byte, error) {
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SchemaVersion
	}
	if err := ValidateProfilesDocument(doc); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode egress profiles: %w", err)
	}
	return append(data, '\n'), nil
}

func decodeStrictJSON(r io.Reader, dst any, maxBytes int) error {
	if r == nil {
		return codedError(CodeInvalidFrame, ErrInvalidFrame, "JSON reader is nil")
	}
	if maxBytes <= 0 {
		return codedError(CodeInvalidConfig, ErrInvalidConfig, "JSON size limit must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return fmt.Errorf("read egress JSON: %w", err)
	}
	if len(data) > maxBytes {
		return codedError(CodeInvalidConfig, ErrInvalidConfig, "JSON exceeds %d bytes", maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode egress JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return codedError(CodeInvalidConfig, ErrInvalidConfig, "JSON contains trailing data")
		}
		return fmt.Errorf("decode egress JSON trailing data: %w", err)
	}
	return nil
}

func encodeStrictJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode egress JSON: %w", err)
	}
	return data, nil
}

// RedactSecrets removes known secret values from diagnostic text. Longer
// values are replaced first so a shorter secret cannot leave a suffix exposed.
func RedactSecrets(text string, secrets ...string) string {
	unique := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			unique[secret] = struct{}{}
		}
	}
	values := make([]string, 0, len(unique))
	for secret := range unique {
		values = append(values, secret)
	}
	sort.Slice(values, func(i, j int) bool {
		if len(values[i]) == len(values[j]) {
			return values[i] < values[j]
		}
		return len(values[i]) > len(values[j])
	})
	for _, secret := range values {
		text = strings.ReplaceAll(text, secret, "[REDACTED]")
	}
	return text
}

// RedactProfile returns a copy safe for diagnostics.
func RedactProfile(profile EgressProfile) EgressProfile {
	copy := profile
	copy.Server.CredentialRef = "[REDACTED]"
	copy.Policy.TargetAllowList = append([]string(nil), profile.Policy.TargetAllowList...)
	copy.Rules = make([]AppRule, len(profile.Rules))
	for i, rule := range profile.Rules {
		copy.Rules[i] = rule
		copy.Rules[i].Protocols = append([]Protocol(nil), rule.Protocols...)
	}
	return copy
}
