package frp

import (
	"strings"
	"testing"
)

func TestLogRingRedactsAndBounds(t *testing.T) {
	var ring logRing
	ring.setSecrets("token-value")
	for i := 0; i < logRingCapacity+10; i++ {
		ring.add("line token=token-value password=secret")
	}
	lines := ring.snapshot()
	if len(lines) != logRingCapacity {
		t.Fatalf("ring length = %d", len(lines))
	}
	if strings.Contains(strings.Join(lines, "\n"), "token-value") {
		t.Fatal("secret remained in logs")
	}
	if !strings.Contains(lines[0], "[已隐藏]") {
		t.Fatal("log line was not redacted")
	}
}
