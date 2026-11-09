package egressgateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLeaseIssuerVerificationLifecycle(t *testing.T) {
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	issuer, clock := testIssuer(start)
	lease, err := issuer.Issue("dev-a", "profile-a", "rule-a", testPolicy(), 2*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if lease.Capability == "" {
		t.Fatal("Issue did not return a capability")
	}
	if lease.ID == "" || lease.Nonce == "" {
		t.Fatal("Issue returned empty id or nonce")
	}
	if lease.PolicyVersion != 7 || lease.Limits.MaxConnections != 4 {
		t.Fatalf("unexpected lease metadata: %+v", lease)
	}

	stored, err := issuer.Get(lease.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Capability != "" {
		t.Fatalf("Get exposed capability %q", stored.Capability)
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal stored lease: %v", err)
	}
	if strings.Contains(string(encoded), lease.Capability) || strings.Contains(string(encoded), "capability") {
		t.Fatalf("stored lease JSON exposed capability: %s", encoded)
	}
	if status, err := issuer.Status(lease.ID); err != nil || status != LeaseStatusActive {
		t.Fatalf("Status = %q, %v", status, err)
	}

	verified, err := issuer.Verify(lease.ID, "dev-a", lease.Capability, 7)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Capability != "" {
		t.Fatal("Verify returned capability")
	}
	if _, err := issuer.Verify(lease.ID, "dev-b", lease.Capability, 7); !errors.Is(err, ErrLeaseUnauthorized) {
		t.Fatalf("wrong device error = %v", err)
	}
	if _, err := issuer.Verify(lease.ID, "dev-a", "wrong-secret", 7); !errors.Is(err, ErrLeaseUnauthorized) {
		t.Fatalf("wrong secret error = %v", err)
	}
	if _, err := issuer.Verify(lease.ID, "dev-a", lease.Capability, 8); !errors.Is(err, ErrPolicyVersionMismatch) {
		t.Fatalf("version mismatch error = %v", err)
	}
	if _, err := issuer.Verify("lease_missing", "dev-a", lease.Capability, 7); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("unknown lease error = %v", err)
	}

	clock.Advance(3 * time.Minute)
	if _, err := issuer.Verify(lease.ID, "dev-a", lease.Capability, 7); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired verify error = %v", err)
	}
	if status, err := issuer.Status(lease.ID); err != nil || status != LeaseStatusExpired {
		t.Fatalf("expired Status = %q, %v", status, err)
	}
	if _, err := issuer.Renew(lease.ID, "dev-a", time.Minute); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired renew error = %v", err)
	}
	if err := issuer.Revoke(lease.ID, RevocationReasonAdministrator); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired revoke error = %v", err)
	}
}

func TestLeaseIssuerRevocationAndBinding(t *testing.T) {
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	issuer, _ := testIssuer(start)
	lease, err := issuer.Issue("dev-a", "profile-a", "rule-a", testPolicy(), time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := issuer.Renew(lease.ID, "dev-b", time.Minute); !errors.Is(err, ErrLeaseUnauthorized) {
		t.Fatalf("wrong-device renew error = %v", err)
	}
	if _, err := issuer.Renew("lease_missing", "dev-a", time.Minute); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("unknown renew error = %v", err)
	}
	if err := issuer.RevokeForDevice(lease.ID, "dev-b", RevocationReasonClientRequested); !errors.Is(err, ErrLeaseUnauthorized) {
		t.Fatalf("wrong-device revoke error = %v", err)
	}
	if err := issuer.RevokeForDevice(lease.ID, "dev-a", RevocationReasonClientRequested); err != nil {
		t.Fatalf("RevokeForDevice: %v", err)
	}
	if _, err := issuer.Verify(lease.ID, "dev-a", lease.Capability, 7); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revoked verify error = %v", err)
	}
	if _, err := issuer.Renew(lease.ID, "dev-a", time.Minute); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revoked renew error = %v", err)
	}
	if err := issuer.Revoke(lease.ID, RevocationReasonAdministrator); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("second revoke error = %v", err)
	}
	if status, err := issuer.Status(lease.ID); err != nil || status != LeaseStatusRevoked {
		t.Fatalf("revoked Status = %q, %v", status, err)
	}
	revoked, err := issuer.Get(lease.ID)
	if err != nil {
		t.Fatalf("Get revoked: %v", err)
	}
	if revoked.RevokedAt == nil || revoked.RevocationReason != RevocationReasonClientRequested {
		t.Fatalf("revocation metadata missing: %+v", revoked)
	}
}

func TestLeaseIssuerValidationAndRenewal(t *testing.T) {
	issuer, _ := testIssuer(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	policy := testPolicy()
	policy.DNSPolicy = DNSPolicy("unknown")
	if _, err := issuer.Issue("dev-a", "profile-a", "rule-a", policy, time.Minute); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid policy error = %v", err)
	}
	if _, err := issuer.Issue("dev-a", "profile-a", "rule-a", testPolicy(), 2*time.Hour); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("excessive ttl error = %v", err)
	}
	if _, err := issuer.Issue("dev/a", "profile-a", "rule-a", testPolicy(), time.Minute); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("invalid id error = %v", err)
	}
	if _, err := issuer.Issue("dev-a", "profile-a", "rule-a", testPolicy(), -time.Minute); err != nil {
		t.Fatalf("non-positive ttl should use the default: %v", err)
	}
}

func TestLeaseIssuerConcurrentOperations(t *testing.T) {
	issuer, _ := testIssuer(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	const workers = 64
	var wait sync.WaitGroup
	errs := make(chan error, workers*2)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, err := issuer.Issue(fmt.Sprintf("dev-%d", worker), fmt.Sprintf("profile-%d", worker), fmt.Sprintf("rule-%d", worker), testPolicy(), time.Minute)
			if err != nil {
				errs <- err
				return
			}
			renewed, err := issuer.Renew(lease.ID, lease.DeviceID, 2*time.Minute)
			if err != nil {
				errs <- err
				return
			}
			if renewed.Capability != "" {
				errs <- errors.New("renew exposed capability")
				return
			}
			if _, err := issuer.Status(lease.ID); err != nil {
				errs <- err
				return
			}
			if worker%2 == 0 {
				if err := issuer.RevokeForDevice(lease.ID, lease.DeviceID, RevocationReasonAdministrator); err != nil {
					errs <- err
				}
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent operation: %v", err)
	}
}
