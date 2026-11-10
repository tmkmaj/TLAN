package network

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

func TestRelaySnapshotOmitsSecretAndDisconnectDeviceClosesOnlyTarget(t *testing.T) {
	broker := NewRelayBroker(1024)
	first, err := broker.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := broker.CreateSession(core.DeviceID("device-c"), core.DeviceID("device-d"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, err := broker.Attach(first, core.DeviceID("device-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.Attach(first, core.DeviceID("device-b"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := broker.Attach(second, core.DeviceID("device-c"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := broker.Attach(second, core.DeviceID("device-d"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	defer c.Close()
	defer d.Close()

	snapshot := broker.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot length = %d, want 2", len(snapshot))
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || containsAny(string(raw), first.Secret, second.Secret) {
		t.Fatalf("snapshot leaked a relay secret: %s", raw)
	}
	if broker.DisconnectDevice(core.DeviceID("device-a")) != 1 {
		t.Fatal("disconnect did not close exactly one session")
	}
	if err := a.Send([]byte("closed")); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("disconnected device send error = %v", err)
	}
	if err := c.Send([]byte("still-open")); err != nil {
		t.Fatal(err)
	}
	message, err := d.Receive()
	if err != nil || string(message.Data) != "still-open" {
		t.Fatalf("unrelated session message = %q, err=%v", message.Data, err)
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) > 0 && (len(value) >= len(needle)) {
			for i := 0; i+len(needle) <= len(value); i++ {
				if value[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}