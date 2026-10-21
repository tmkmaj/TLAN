package targetgateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestTargetValidate(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	tests := []struct {
		name    string
		target  Target
		wantErr string
	}{
		{name: "private ten", target: Target{IPv4: netip.MustParseAddr("10.240.0.2"), Port: 8080, DeviceID: "device-b"}},
		{name: "cgnat mesh", target: Target{IPv4: netip.MustParseAddr("100.64.0.2"), Port: 8080, DeviceID: "device-b", PublicKey: key}},
		{name: "public target", target: Target{IPv4: netip.MustParseAddr("1.1.1.1"), Port: 80, DeviceID: "device-b"}, wantErr: "outside the allowed"},
		{name: "loopback target", target: Target{IPv4: netip.MustParseAddr("127.0.0.1"), Port: 80, DeviceID: "device-b"}, wantErr: "not a usable"},
		{name: "mapped ipv4", target: Target{IPv4: netip.MustParseAddr("::ffff:10.240.0.2"), Port: 80, DeviceID: "device-b"}, wantErr: "literal IPv4"},
		{name: "missing device", target: Target{IPv4: netip.MustParseAddr("10.240.0.2"), Port: 80}, wantErr: "device ID"},
		{name: "missing port", target: Target{IPv4: netip.MustParseAddr("10.240.0.2"), DeviceID: "device-b"}, wantErr: "port"},
		{name: "bad public key", target: Target{IPv4: netip.MustParseAddr("10.240.0.2"), Port: 80, DeviceID: "device-b", PublicKey: "bad"}, wantErr: "public key"},
		{name: "bad network", target: Target{NetworkID: "bad network", IPv4: netip.MustParseAddr("10.240.0.2"), Port: 80, DeviceID: "device-b"}, wantErr: "network ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.target.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	target := testTarget(8080)
	cfg := Config{Protocol: " TCP ", Target: target, Lease: newLeaseFixture(), Dialer: &testDialer{}}
	normalized, err := cfg.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Protocol != ProtocolTCP || normalized.LeasePollInterval != DefaultLeasePollInterval || normalized.MaxConnections != DefaultMaxConnections {
		t.Fatalf("unexpected defaults: %+v", normalized)
	}
	if normalized.ListenPort != 0 {
		t.Fatalf("listen port changed: %d", normalized.ListenPort)
	}

	bad := []Config{
		{Protocol: ProtocolTCP, Target: target, Dialer: &testDialer{}},
		{Protocol: ProtocolTCP, Target: target, Lease: newLeaseFixture()},
		{Protocol: "sctp", Target: target, Lease: newLeaseFixture(), Dialer: &testDialer{}},
		{Protocol: ProtocolTCP, Target: target, Lease: newLeaseFixture(), Dialer: &testDialer{}, MaxDatagramSize: 70000},
	}
	for _, candidate := range bad {
		if _, err := candidate.normalized(); err == nil {
			t.Fatalf("normalized() accepted invalid config %+v", candidate)
		}
	}
}

func TestStartRequiresContext(t *testing.T) {
	_, err := Start(nil, Config{})
	if err == nil {
		t.Fatal("Start accepted a nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Start(ctx, Config{})
	if err == nil {
		t.Fatal("Start accepted a canceled context")
	}
}

func TestLeaseRequiresGenerationAndDone(t *testing.T) {
	if err := validateLease(Lease{}); !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatalf("empty lease error = %v", err)
	}
	done := make(chan struct{})
	if err := validateLease(Lease{Generation: 1, Done: done}); err != nil {
		t.Fatalf("valid lease error = %v", err)
	}
	close(done)
	if err := validateLease(Lease{Generation: 1, Done: done}); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revoked lease error = %v", err)
	}
}
