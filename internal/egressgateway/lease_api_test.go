package egressgateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type headerAuthenticator struct{}

func (headerAuthenticator) Authenticate(request *http.Request) (string, error) {
	deviceID := strings.TrimSpace(request.Header.Get("X-Device-ID"))
	if deviceID == "" {
		return "", errors.New("missing device identity")
	}
	return deviceID, nil
}

type leaseCreateResponse struct {
	ID            string      `json:"id"`
	DeviceID      string      `json:"device_id"`
	ProfileID     string      `json:"profile_id"`
	RuleID        string      `json:"rule_id"`
	PolicyVersion int         `json:"policy_version"`
	ExpiresAt     time.Time   `json:"expires_at"`
	Capability    string      `json:"capability"`
	Status        LeaseStatus `json:"status"`
}

func newLeaseAPITestServer(t *testing.T) (*httptest.Server, *testClock) {
	t.Helper()
	issuer, clock := testIssuer(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	server := httptest.NewServer(NewLeaseAPI(issuer, headerAuthenticator{}))
	t.Cleanup(server.Close)
	return server, clock
}

func createLeaseRequestJSON(t *testing.T, deviceID string) []byte {
	t.Helper()
	body, err := json.Marshal(CreateLeaseRequest{
		ProfileID: "profile-a",
		RuleID:    "rule-a",
		Policy:    testPolicy(),
	})
	if err != nil {
		t.Fatalf("marshal create request: %v", err)
	}
	_ = deviceID
	return body
}

func doAPIRequest(t *testing.T, client *http.Client, method, url, deviceID string, body []byte, contentType string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if deviceID != "" {
		request.Header.Set("X-Device-ID", deviceID)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response.StatusCode, responseBody
}

func TestLeaseAPICreateGetAndStrictBody(t *testing.T) {
	server, _ := newLeaseAPITestServer(t)
	base := server.URL + "/api/v1/egress/leases"
	status, responseBody := doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", createLeaseRequestJSON(t, "dev-a"), "application/json")
	if status != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", status, responseBody)
	}
	var created leaseCreateResponse
	if err := json.Unmarshal(responseBody, &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" || created.DeviceID != "dev-a" || created.ProfileID != "profile-a" || created.RuleID != "rule-a" {
		t.Fatalf("unexpected created lease: %+v", created)
	}
	if created.Capability == "" || created.Status != LeaseStatusActive || created.PolicyVersion != 7 {
		t.Fatalf("missing capability/status/version: %+v", created)
	}

	leaseURL := base + "/" + created.ID
	status, responseBody = doAPIRequest(t, server.Client(), http.MethodGet, leaseURL, "dev-a", nil, "")
	if status != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", status, responseBody)
	}
	var raw map[string]any
	if err := json.Unmarshal(responseBody, &raw); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if _, exists := raw["capability"]; exists {
		t.Fatalf("GET exposed capability: %s", responseBody)
	}
	if raw["status"] != string(LeaseStatusActive) {
		t.Fatalf("GET status = %v", raw["status"])
	}

	status, _ = doAPIRequest(t, server.Client(), http.MethodGet, leaseURL, "dev-b", nil, "")
	if status != http.StatusForbidden {
		t.Fatalf("wrong-device GET status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodGet, base+"/lease_missing", "dev-a", nil, "")
	if status != http.StatusNotFound {
		t.Fatalf("unknown GET status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "", createLeaseRequestJSON(t, ""), "application/json")
	if status != http.StatusUnauthorized {
		t.Fatalf("missing-auth status = %d", status)
	}

	var createFields map[string]any
	if err := json.Unmarshal(createLeaseRequestJSON(t, "dev-a"), &createFields); err != nil {
		t.Fatalf("decode create fields: %v", err)
	}
	createFields["unexpected"] = true
	unknownFieldBody, _ := json.Marshal(createFields)
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", unknownFieldBody, "application/json")
	if status != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d", status)
	}

	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", createLeaseRequestJSON(t, "dev-a"), "text/plain")
	if status != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong-content-type status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", []byte(`{"profile_id":`), "application/json")
	if status != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", status)
	}
	oversized := []byte(`{"profile_id":"` + strings.Repeat("a", leaseAPIMaxBody) + `"}`)
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", oversized, "application/json")
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodGet, base, "dev-a", nil, "")
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d", status)
	}
}

func TestLeaseAPIRenewRevokeAndExpiry(t *testing.T) {
	server, clock := newLeaseAPITestServer(t)
	base := server.URL + "/api/v1/egress/leases"

	create := func(deviceID string) leaseCreateResponse {
		t.Helper()
		status, body := doAPIRequest(t, server.Client(), http.MethodPost, base, deviceID, createLeaseRequestJSON(t, deviceID), "application/json")
		if status != http.StatusCreated {
			t.Fatalf("create status = %d, body=%s", status, body)
		}
		var response leaseCreateResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		return response
	}

	revoked := create("dev-a")
	revokeBody := []byte(`{"reason":"client_requested"}`)
	status, body := doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+revoked.ID+"/revoke", "dev-a", revokeBody, "application/json")
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", status, body)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodGet, base+"/"+revoked.ID, "dev-a", nil, "")
	if status != http.StatusConflict {
		t.Fatalf("revoked GET status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+revoked.ID+"/renew", "dev-a", []byte(`{}`), "application/json")
	if status != http.StatusConflict {
		t.Fatalf("revoked renew status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+revoked.ID+"/revoke", "dev-a", revokeBody, "application/json")
	if status != http.StatusConflict {
		t.Fatalf("second revoke status = %d", status)
	}

	active := create("dev-a")
	status, body = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+active.ID+"/renew", "dev-a", []byte(`{"ttl_seconds":120}`), "application/json")
	if status != http.StatusOK {
		t.Fatalf("renew status = %d, body=%s", status, body)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+active.ID+"/renew", "dev-b", []byte(`{}`), "application/json")
	if status != http.StatusForbidden {
		t.Fatalf("wrong-device renew status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+active.ID+"/revoke", "dev-b", revokeBody, "application/json")
	if status != http.StatusForbidden {
		t.Fatalf("wrong-device revoke status = %d", status)
	}

	clock.Advance(3 * time.Minute)
	status, _ = doAPIRequest(t, server.Client(), http.MethodGet, base+"/"+active.ID, "dev-a", nil, "")
	if status != http.StatusGone {
		t.Fatalf("expired GET status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/"+active.ID+"/renew", "dev-a", []byte(`{}`), "application/json")
	if status != http.StatusGone {
		t.Fatalf("expired renew status = %d", status)
	}

	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base+"/lease_missing/renew", "dev-a", []byte(`{}`), "application/json")
	if status != http.StatusNotFound {
		t.Fatalf("unknown renew status = %d", status)
	}
	status, _ = doAPIRequest(t, server.Client(), http.MethodPost, base, "dev-a", []byte(`{"profile_id":"p","rule_id":"r","policy":{},"ttl_seconds":-1}`), "application/json")
	if status != http.StatusBadRequest {
		t.Fatalf("negative TTL status = %d", status)
	}
}
