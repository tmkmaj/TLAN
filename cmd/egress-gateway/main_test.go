package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egressgateway"
)

func TestRunCheckDoesNotApplyNAT(t *testing.T) {
	materials := writeTestMaterials(t)
	configPath := writeTestConfig(t, materials)
	nat := newFakeNAT()
	dependencies := runtimeDependencies{
		newNAT: func(egressgateway.NATConfig) (natLifecycle, error) {
			return nat, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", configPath, "-check"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("run -check exit code = %d, stderr=%s", code, stderr.String())
	}
	detect, plan, apply, rollback := nat.counts()
	if detect == 0 || plan == 0 {
		t.Fatalf("check did not validate capabilities: detect=%d plan=%d", detect, plan)
	}
	if apply != 0 || rollback != 0 {
		t.Fatalf("check changed NAT state: apply=%d rollback=%d", apply, rollback)
	}
	if !strings.Contains(stderr.String(), "configuration check passed") {
		t.Fatalf("check output missing success message: %s", stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, materials.token) {
		t.Fatal("bearer token was written to command output")
	}
}

func TestRunPrintPlanDoesNotApplyNAT(t *testing.T) {
	materials := writeTestMaterials(t)
	configPath := writeTestConfig(t, materials)
	nat := newFakeNAT()
	dependencies := runtimeDependencies{
		newNAT: func(egressgateway.NATConfig) (natLifecycle, error) {
			return nat, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", configPath, "-print-plan"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("run -print-plan exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "backend: fake") {
		t.Fatalf("plan output = %q", stdout.String())
	}
	_, _, apply, rollback := nat.counts()
	if apply != 0 || rollback != 0 {
		t.Fatalf("print-plan changed NAT state: apply=%d rollback=%d", apply, rollback)
	}
}

func TestRunCheckReportsCapabilityFailure(t *testing.T) {
	materials := writeTestMaterials(t)
	configPath := writeTestConfig(t, materials)
	nat := newFakeNAT()
	nat.capabilities.IPForwardStateRead = false
	dependencies := runtimeDependencies{
		newNAT: func(egressgateway.NATConfig) (natLifecycle, error) {
			return nat, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", configPath, "-check"}, &stdout, &stderr, dependencies)
	if code == 0 {
		t.Fatalf("run -check succeeded with unreadable ip_forward, stderr=%s", stderr.String())
	}
	_, _, apply, _ := nat.counts()
	if apply != 0 {
		t.Fatalf("failed check applied NAT %d times", apply)
	}
}

func TestServeGatewayAppliesAndRollsBackNAT(t *testing.T) {
	config, materials := loadTestConfig(t)
	config.Listen = "127.0.0.1:0"
	config.Control.LeaseURL = ""

	tlsConfig, err := loadServerTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := loadBearerAuthenticator(materials.tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	issuer := egressgateway.NewLeaseIssuer(egressgateway.LeaseIssuerConfig{
		GatewayEndpoint: config.Listen,
		DefaultLimits:   config.Limits.gatewayLimits(),
	})
	service, err := newGatewayService(config, issuer, networkDependencies{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	leaseEndpoint, err := resolveLeaseEndpoint(config.Control.LeaseURL)
	if err != nil {
		t.Fatal(err)
	}
	nat := newFakeNAT()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := serveGateway(ctx, config, issuer, service, nat, tlsConfig, authenticator, leaseEndpoint, log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("serve gateway: %v", err)
	}
	_, _, apply, rollback := nat.counts()
	if apply != 1 {
		t.Fatalf("NAT apply count = %d, want 1", apply)
	}
	if rollback != 1 {
		t.Fatalf("NAT rollback count = %d, want 1", rollback)
	}
}

