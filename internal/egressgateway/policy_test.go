package egressgateway

import (
	"errors"
	"net/netip"
	"testing"
)

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	target, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return target
}

func TestClassifyTarget(t *testing.T) {
	tests := []struct {
		target string
		want   TargetClass
	}{
		{"203.0.113.10:443", TargetClassPublic},
		{"10.1.2.3:443", TargetClassPrivate},
		{"127.0.0.1:443", TargetClassLoopback},
		{"169.254.10.1:443", TargetClassLinkLocal},
		{"224.0.0.1:443", TargetClassMulticast},
		{"0.0.0.0:443", TargetClassUnspecified},
		{"169.254.169.254:80", TargetClassCloudMetadata},
		{"[fd00:ec2::254]:443", TargetClassCloudMetadata},
		{"[2001:4860:4860::8888]:443", TargetClassIPv6},
	}
	for _, test := range tests {
		test := test
		t.Run(test.target, func(t *testing.T) {
			target := mustAddrPort(t, test.target)
			if got := ClassifyTarget(target); got != test.want {
				t.Fatalf("ClassifyTarget(%s) = %q, want %q", target, got, test.want)
			}
			if wrapped := NewEgressTarget(target, ProtocolTCP); wrapped.Class != test.want {
				t.Fatalf("NewEgressTarget class = %q, want %q", wrapped.Class, test.want)
			}
		})
	}
}

func TestSessionPolicyRejectsUnsafeTargets(t *testing.T) {
	policy := testPolicy()
	enforcer, err := NewSessionPolicy(policy)
	if err != nil {
		t.Fatalf("NewSessionPolicy: %v", err)
	}
	allowed := mustAddrPort(t, "203.0.113.10:443")
	if err := enforcer.ValidateTarget(allowed, ClassifyTarget(allowed)); err != nil {
		t.Fatalf("allowed target: %v", err)
	}
	if err := enforcer.ValidateEgressTarget(NewEgressTarget(allowed, ProtocolTCP)); err != nil {
		t.Fatalf("allowed egress target: %v", err)
	}
	if err := enforcer.ValidateTarget(allowed, TargetClassPrivate); !errors.Is(err, ErrTargetClassMismatch) {
		t.Fatalf("class mismatch error = %v", err)
	}

	rejected := []struct {
		target string
		class  TargetClass
	}{
		{"127.0.0.1:443", TargetClassLoopback},
		{"10.0.0.1:443", TargetClassPrivate},
		{"169.254.1.1:443", TargetClassLinkLocal},
		{"224.0.0.1:443", TargetClassMulticast},
		{"0.0.0.0:443", TargetClassUnspecified},
		{"169.254.169.254:80", TargetClassCloudMetadata},
		{"[fd00:ec2::254]:80", TargetClassCloudMetadata},
		{"198.18.0.1:443", TargetClassPublic},
	}
	for _, test := range rejected {
		test := test
		t.Run(test.target, func(t *testing.T) {
			target := mustAddrPort(t, test.target)
			err := enforcer.ValidateTarget(target, test.class)
			if test.class == TargetClassPublic {
				if !errors.Is(err, ErrTargetNotAllowed) {
					t.Fatalf("outside-CIDR error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrTargetBlocked) {
				t.Fatalf("unsafe target error = %v", err)
			}
		})
	}

	blockedIPv6 := policy.Clone()
	blockedIPv6.IPv6Policy = IPv6PolicyBlock
	ipv6Enforcer, err := NewSessionPolicy(blockedIPv6)
	if err != nil {
		t.Fatalf("NewSessionPolicy IPv6 block: %v", err)
	}
	ipv6Target := mustAddrPort(t, "[2001:4860:4860::8888]:443")
	if err := ipv6Enforcer.ValidateTarget(ipv6Target, ClassifyTarget(ipv6Target)); !errors.Is(err, ErrIPv6Blocked) {
		t.Fatalf("blocked IPv6 error = %v", err)
	}

	management := mustAddrPort(t, "203.0.113.10:3389")
	if err := enforcer.ValidateTarget(management, ClassifyTarget(management)); !errors.Is(err, ErrManagementPortBlocked) {
		t.Fatalf("management port error = %v", err)
	}

	blockedClass := policy.Clone()
	blockedClass.BlockedCategories = []TargetClass{TargetClassPublic}
	blockedEnforcer, err := NewSessionPolicy(blockedClass)
	if err != nil {
		t.Fatalf("NewSessionPolicy blocked class: %v", err)
	}
	if err := blockedEnforcer.ValidateTarget(allowed, ClassifyTarget(allowed)); !errors.Is(err, ErrTargetBlocked) {
		t.Fatalf("blocked category error = %v", err)
	}
}

func TestSessionPolicyDNS(t *testing.T) {
	policy := testPolicy()
	enforcer, err := NewSessionPolicy(policy)
	if err != nil {
		t.Fatalf("NewSessionPolicy: %v", err)
	}
	allowedDNS := mustAddrPort(t, "8.8.8.8:53")
	if err := enforcer.ValidateTarget(allowedDNS, ClassifyTarget(allowedDNS)); err != nil {
		t.Fatalf("gateway resolver: %v", err)
	}
	otherDNS := mustAddrPort(t, "198.51.100.53:53")
	if err := enforcer.ValidateTarget(otherDNS, ClassifyTarget(otherDNS)); !errors.Is(err, ErrDNSResolverDenied) {
		t.Fatalf("non-gateway resolver error = %v", err)
	}

	blocked := policy.Clone()
	blocked.DNSPolicy = DNSPolicyBlock
	blocked.DNSResolvers = nil
	blockedEnforcer, err := NewSessionPolicy(blocked)
	if err != nil {
		t.Fatalf("NewSessionPolicy DNS block: %v", err)
	}
	if err := blockedEnforcer.ValidateTarget(allowedDNS, ClassifyTarget(allowedDNS)); !errors.Is(err, ErrDNSBlocked) {
		t.Fatalf("blocked DNS error = %v", err)
	}
}

func TestPolicyValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"missing protocols", func(policy *Policy) { policy.AllowedProtocols = nil }},
		{"unknown protocol", func(policy *Policy) { policy.AllowedProtocols = []Protocol{"icmp"} }},
		{"missing CIDR", func(policy *Policy) { policy.AllowedTargetCIDRs = nil }},
		{"invalid CIDR", func(policy *Policy) { policy.AllowedTargetCIDRs = []string{"not-a-cidr"} }},
		{"host bits", func(policy *Policy) { policy.AllowedTargetCIDRs = []string{"203.0.113.7/24"} }},
		{"unknown category", func(policy *Policy) { policy.BlockedCategories = []TargetClass{"unknown"} }},
		{"unknown IPv6", func(policy *Policy) { policy.IPv6Policy = "maybe" }},
		{"unknown DNS", func(policy *Policy) { policy.DNSPolicy = "maybe" }},
		{"missing resolver", func(policy *Policy) { policy.DNSResolvers = nil }},
		{"invalid limits", func(policy *Policy) { policy.Limits.MaxBytes = -1 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			test.mutate(&policy)
			if err := policy.Validate(); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestQuotaConnectionAndByteBudgets(t *testing.T) {
	policy := testPolicy()
	policy.Limits = Limits{MaxConnections: 2, MaxBytes: 10, MaxRateBPS: 100}
	enforcer, err := NewSessionPolicy(policy)
	if err != nil {
		t.Fatalf("NewSessionPolicy: %v", err)
	}
	if err := enforcer.AcquireConnection(ProtocolTCP); err != nil {
		t.Fatalf("acquire tcp: %v", err)
	}
	if err := enforcer.AcquireConnection(ProtocolUDP); err != nil {
		t.Fatalf("acquire udp: %v", err)
	}
	if err := enforcer.AcquireConnection(ProtocolTCP); !errors.Is(err, ErrConnectionQuota) {
		t.Fatalf("connection quota error = %v", err)
	}
	snapshot := enforcer.QuotaSnapshot()
	if snapshot.Total != 2 || snapshot.TCP != 1 || snapshot.UDP != 1 {
		t.Fatalf("unexpected connection snapshot: %+v", snapshot)
	}

	enforcer.ReleaseConnection(ProtocolTCP)
	if err := enforcer.AcquireConnection(ProtocolUDP); err != nil {
		t.Fatalf("reuse released slot: %v", err)
	}
	snapshot = enforcer.QuotaSnapshot()
	if snapshot.Total != 2 || snapshot.TCP != 0 || snapshot.UDP != 2 {
		t.Fatalf("unexpected reused snapshot: %+v", snapshot)
	}
	enforcer.ReleaseConnection(ProtocolUDP)
	enforcer.ReleaseConnection(ProtocolUDP)
	enforcer.ReleaseConnection(ProtocolUDP)
	if got := enforcer.QuotaSnapshot().Total; got != 0 {
		t.Fatalf("extra releases underflowed total to %d", got)
	}

	if err := enforcer.ConsumeBytes(6); err != nil {
		t.Fatalf("consume 6: %v", err)
	}
	if err := enforcer.ConsumeBytes(5); !errors.Is(err, ErrByteQuota) {
		t.Fatalf("byte quota error = %v", err)
	}
	if err := enforcer.ConsumeBytes(4); err != nil {
		t.Fatalf("consume remaining 4: %v", err)
	}
	if err := enforcer.ConsumeBytes(1); !errors.Is(err, ErrByteQuota) {
		t.Fatalf("exhausted byte quota error = %v", err)
	}
	if got := enforcer.QuotaSnapshot().Bytes; got != 10 {
		t.Fatalf("bytes = %d, want 10", got)
	}
}

func TestSessionPolicyProtocolDenied(t *testing.T) {
	policy := testPolicy()
	policy.AllowedProtocols = []Protocol{ProtocolTCP}
	enforcer, err := NewSessionPolicy(policy)
	if err != nil {
		t.Fatalf("NewSessionPolicy: %v", err)
	}
	if err := enforcer.AcquireConnection(ProtocolUDP); !errors.Is(err, ErrProtocolDenied) {
		t.Fatalf("UDP protocol error = %v", err)
	}
}
