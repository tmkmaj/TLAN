package egressgateway

import (
	"sync"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

func testPolicy() Policy {
	return Policy{
		Version:            7,
		AllowedProtocols:   []Protocol{ProtocolTCP, ProtocolUDP},
		AllowedTargetCIDRs: []string{"203.0.113.0/24", "198.51.100.0/24", "8.8.8.8/32", "2001:4860:4860::/48"},
		IPv6Policy:         IPv6PolicyAllowPublic,
		DNSPolicy:          DNSPolicyRemote,
		DNSResolvers:       []string{"8.8.8.8"},
		Limits: Limits{
			MaxConnections: 4,
			MaxBytes:       1024,
			MaxRateBPS:     1024,
		},
	}
}

func testIssuer(now time.Time) (*LeaseIssuer, *testClock) {
	clock := newTestClock(now)
	return NewLeaseIssuer(LeaseIssuerConfig{
		Now:             clock.Now,
		GatewayEndpoint: "https://egress.example:443",
		DefaultTTL:      time.Minute,
		MaxTTL:          time.Hour,
	}), clock
}
