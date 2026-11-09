package egressgateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const leaseAPIMaxBody = 64 << 10

// DeviceAuthenticator authenticates the caller and returns its trusted device
// identifier. Egress leases are always scoped to this identifier, never to a
// device ID supplied in the request body.
type DeviceAuthenticator interface {
	Authenticate(*http.Request) (deviceID string, err error)
}

// LeaseAPI serves the versioned egress lease routes. It can be mounted beside
// the existing control-plane handler without modifying that package.
type LeaseAPI struct {
	issuer        *LeaseIssuer
	authenticator DeviceAuthenticator
	maxBody       int64
}

// NewLeaseAPI constructs an HTTP handler. A nil authenticator fails closed.
func NewLeaseAPI(issuer *LeaseIssuer, authenticator DeviceAuthenticator) *LeaseAPI {
	return &LeaseAPI{issuer: issuer, authenticator: authenticator, maxBody: leaseAPIMaxBody}
}

// NewLeaseHandler is an alias for NewLeaseAPI.
func NewLeaseHandler(issuer *LeaseIssuer, authenticator DeviceAuthenticator) http.Handler {
	return NewLeaseAPI(issuer, authenticator)
}

// CreateLeaseRequest is the strict JSON body for lease creation.
type CreateLeaseRequest struct {
	ProfileID  string `json:"profile_id"`
	RuleID     string `json:"rule_id"`
	Policy     Policy `json:"policy"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// RenewLeaseRequest is the strict JSON body for renewal.
type RenewLeaseRequest struct {
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// RevokeLeaseRequest is the strict JSON body for revocation.
type RevokeLeaseRequest struct {
	Reason RevocationReason `json:"reason"`
}

// LeaseAPIResponse is returned by mutation and lookup routes. It omits the
// capability for every response except the immediate creation response.
type LeaseAPIResponse struct {
	Lease
	Status LeaseStatus `json:"status"`
}

type revokeResponse struct {
	ID               string           `json:"id"`
	Status           LeaseStatus      `json:"status"`
	RevocationReason RevocationReason `json:"revocation_reason"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
}

// ServeHTTP implements the four plan routes.
func (a *LeaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.issuer == nil {
		writeAPIError(w, http.StatusInternalServerError, "egress lease API is not configured")
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/api/v1/egress/leases" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		a.createLease(w, r)
		return
	}
	const prefix = "/api/v1/egress/leases/"
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		a.getLease(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" {
		switch parts[1] {
		case "renew":
			if r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodPost)
				return
			}
			a.renewLease(w, r, parts[0])
			return
		case "revoke":
			if r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodPost)
				return
			}
			a.revokeLease(w, r, parts[0])
			return
		}
	}
	http.NotFound(w, r)
}

func (a *LeaseAPI) createLease(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	var request CreateLeaseRequest
	if err := a.decodeJSON(w, r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	ttl, err := durationFromSeconds(request.TTLSeconds)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	lease, err := a.issuer.Issue(deviceID, request.ProfileID, request.RuleID, request.Policy, ttl)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, LeaseAPIResponse{Lease: lease, Status: LeaseStatusActive})
}

func (a *LeaseAPI) getLease(w http.ResponseWriter, r *http.Request, leaseID string) {
	deviceID, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	lease, err := a.issuer.Get(leaseID)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	if lease.DeviceID != deviceID {
		writeAPIError(w, http.StatusForbidden, "lease belongs to another device")
		return
	}
	status, err := a.issuer.Status(leaseID)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	if status != LeaseStatusActive {
		writeLeaseStatusError(w, status)
		return
	}
	writeJSON(w, http.StatusOK, LeaseAPIResponse{Lease: lease, Status: status})
}

func (a *LeaseAPI) renewLease(w http.ResponseWriter, r *http.Request, leaseID string) {
	deviceID, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	var request RenewLeaseRequest
	if err := a.decodeJSON(w, r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	ttl, err := durationFromSeconds(request.TTLSeconds)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	lease, err := a.issuer.Renew(leaseID, deviceID, ttl)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, LeaseAPIResponse{Lease: lease, Status: LeaseStatusActive})
}

func (a *LeaseAPI) revokeLease(w http.ResponseWriter, r *http.Request, leaseID string) {
	deviceID, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	var request RevokeLeaseRequest
	if err := a.decodeJSON(w, r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := a.issuer.RevokeForDevice(leaseID, deviceID, request.Reason); err != nil {
		writeLeaseError(w, err)
		return
	}
	lease, err := a.issuer.Get(leaseID)
	if err != nil {
		writeLeaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{
		ID: lease.ID, Status: LeaseStatusRevoked,
		RevocationReason: lease.RevocationReason, RevokedAt: lease.RevokedAt,
	})
}
func (a *LeaseAPI) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	if a.authenticator == nil {
		writeAPIError(w, http.StatusUnauthorized, "device authentication required")
		return "", false
	}
	deviceID, err := a.authenticator.Authenticate(r)
	if err != nil || validateLeaseIdentifier(deviceID, "device_id") != nil {
		writeAPIError(w, http.StatusUnauthorized, "device authentication failed")
		return "", false
	}
	return strings.TrimSpace(deviceID), true
}

var errUnsupportedMediaType = errors.New("content type must be application/json")

func (a *LeaseAPI) decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errUnsupportedMediaType
		}
	}
	limited := http.MaxBytesReader(w, r.Body, a.maxBody)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func durationFromSeconds(seconds int64) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("%w: ttl_seconds must not be negative", ErrInvalidLease)
	}
	if seconds == 0 {
		return 0, nil
	}
	if seconds > int64(MaxLeaseTTL/time.Second) {
		return 0, fmt.Errorf("%w: ttl_seconds exceeds maximum", ErrInvalidLease)
	}
	return time.Duration(seconds) * time.Second, nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnsupportedMediaType) {
		writeAPIError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	writeAPIError(w, http.StatusBadRequest, "invalid JSON request body")
}

func writeLeaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidLease), errors.Is(err, ErrInvalidPolicy), errors.Is(err, ErrInvalidTarget):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrLeaseNotFound):
		writeAPIError(w, http.StatusNotFound, "egress lease not found")
	case errors.Is(err, ErrLeaseUnauthorized):
		writeAPIError(w, http.StatusForbidden, "egress lease is bound to another device")
	case errors.Is(err, ErrLeaseRevoked):
		writeAPIError(w, http.StatusConflict, "egress lease is revoked")
	case errors.Is(err, ErrLeaseExpired):
		writeAPIError(w, http.StatusGone, "egress lease is expired")
	case errors.Is(err, ErrPolicyVersionMismatch):
		writeAPIError(w, http.StatusConflict, "egress policy version mismatch")
	default:
		writeAPIError(w, http.StatusInternalServerError, "egress lease operation failed")
	}
}

func writeLeaseStatusError(w http.ResponseWriter, status LeaseStatus) {
	switch status {
	case LeaseStatusRevoked:
		writeAPIError(w, http.StatusConflict, "egress lease is revoked")
	case LeaseStatusExpired:
		writeAPIError(w, http.StatusGone, "egress lease is expired")
	default:
		writeAPIError(w, http.StatusInternalServerError, "egress lease has an unknown status")
	}
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
}
