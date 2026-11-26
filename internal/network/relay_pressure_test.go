package network

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

func newRelayPair(t *testing.T, limits RelayLimits) (*RelayBroker, *RelayConnection, *RelayConnection) {
	t.Helper()
	broker := NewRelayBrokerWithLimits(limits)
	const source = core.DeviceID("device-a")
	const target = core.DeviceID("device-b")
	ticket, err := broker.CreateSession(source, target, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, err := broker.Attach(ticket, source)
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.Attach(ticket, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
		_ = broker.Close()
	})
	return broker, a, b
}

func assertRelayCounters(t *testing.T, got, want RelayStats) {
	t.Helper()
	if got.Enqueued != want.Enqueued ||
		got.DroppedQueueFull != want.DroppedQueueFull ||
		got.DroppedLowPriority != want.DroppedLowPriority ||
		got.DroppedOldest != want.DroppedOldest ||
		got.BackpressureEvents != want.BackpressureEvents ||
		got.WriteErrors != want.WriteErrors {
		t.Fatalf("relay counters = %+v, want %+v", got, want)
	}
}

func TestRelayBrokerLowPriorityDroppedWhenFull(t *testing.T) {
	broker, a, b := newRelayPair(t, RelayLimits{QueueDepth: 1})
	if err := a.Send([]byte("durable")); err != nil {
		t.Fatal(err)
	}
	err := a.SendWithPriority([]byte("best-effort"), RelayPriorityLow)
	var pressure *RelayBackpressureError
	if !errors.As(err, &pressure) {
		t.Fatalf("low-priority send error = %v, want RelayBackpressureError", err)
	}
	if pressure.Reason != RelayDropLowPriority || pressure.Priority != RelayPriorityLow {
		t.Fatalf("backpressure = %+v, want low-priority drop", pressure)
	}
	if !errors.Is(err, ErrRelayBackpressure) || !IsRelayBackpressure(err) {
		t.Fatalf("error %v is not recognizable as relay backpressure", err)
	}
	want := RelayStats{
		Enqueued:           1,
		DroppedQueueFull:   1,
		DroppedLowPriority: 1,
		BackpressureEvents: 1,
	}
	assertRelayCounters(t, a.Stats(), want)
	assertRelayCounters(t, b.Stats(), want)
	assertRelayCounters(t, broker.Stats(), want)
	message, err := b.Receive()
	if err != nil || string(message.Data) != "durable" {
		t.Fatalf("receive = %q, %v; low-priority packet must not displace the durable one", message.Data, err)
	}
}

func TestRelayBrokerNormalPriorityEvictsOldest(t *testing.T) {
	_, a, b := newRelayPair(t, RelayLimits{QueueDepth: 2})
	for _, payload := range []string{"one", "two"} {
		if err := a.Send([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Send([]byte("three")); err != nil {
		t.Fatalf("normal send after drop-oldest = %v", err)
	}
	want := RelayStats{
		Enqueued:           3,
		DroppedQueueFull:   1,
		DroppedOldest:      1,
		BackpressureEvents: 1,
	}
	assertRelayCounters(t, a.Stats(), want)
	assertRelayCounters(t, b.Stats(), want)
	stats := b.Stats()
	if stats.QueueDepth != 2 || stats.QueueCapacity != 2 {
		t.Fatalf("queue = %d/%d, want 2/2", stats.QueueDepth, stats.QueueCapacity)
	}
	for _, want := range []string{"two", "three"} {
		message, err := b.Receive()
		if err != nil || string(message.Data) != want {
			t.Fatalf("receive = %q, %v; want %q", message.Data, err, want)
		}
	}
}

func TestRelayBrokerConcurrentLowPriorityStats(t *testing.T) {
	const attempts = 64
	broker, a, b := newRelayPair(t, RelayLimits{QueueDepth: 1})
	var enqueued, backpressured, unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := a.SendWithPriority([]byte{byte(i)}, RelayPriorityLow)
			switch {
			case err == nil:
				enqueued.Add(1)
			case IsRelayBackpressure(err):
				backpressured.Add(1)
			default:
				unexpected.Add(1)
				t.Errorf("send %d error = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("unexpected send errors = %d", unexpected.Load())
	}
	if enqueued.Load() != 1 || backpressured.Load() != attempts-1 {
		t.Fatalf("enqueued = %d, backpressured = %d", enqueued.Load(), backpressured.Load())
	}
	want := RelayStats{
		Enqueued:           1,
		DroppedQueueFull:   attempts - 1,
		DroppedLowPriority: attempts - 1,
		BackpressureEvents: attempts - 1,
	}
	assertRelayCounters(t, a.Stats(), want)
	assertRelayCounters(t, b.Stats(), want)
	assertRelayCounters(t, broker.Stats(), want)
}

func TestRelayContextCancellationReturnsContextError(t *testing.T) {
	_, a, b := newRelayPair(t, RelayLimits{QueueDepth: 1})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.SendContext(canceled, []byte("never-enqueued")); !errors.Is(err, context.Canceled) {
		t.Fatalf("send with canceled context = %v", err)
	}
	if _, err := b.ReceiveContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive with canceled context = %v", err)
	}
	assertRelayCounters(t, b.Stats(), RelayStats{})

	if err := a.Send([]byte("keep")); err != nil {
		t.Fatal(err)
	}
	canceledAgain, cancelAgain := context.WithCancel(context.Background())
	cancelAgain()
	if err := a.SendContext(canceledAgain, []byte("must-not-evict")); !errors.Is(err, context.Canceled) {
		t.Fatalf("full-queue send with canceled context = %v", err)
	}
	assertRelayCounters(t, b.Stats(), RelayStats{Enqueued: 1})
	message, err := b.Receive()
	if err != nil || string(message.Data) != "keep" {
		t.Fatalf("receive = %q, %v; cancellation must not evict queued data", message.Data, err)
	}
}

func newPipeStreamRelay(t *testing.T, depth int) (*StreamRelay, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	relay := newStreamRelayWithQueue(client, bufio.NewReader(client), depth)
	t.Cleanup(func() {
		_ = relay.Close()
		_ = server.Close()
	})
	return relay, server
}

func readPipeFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	payload, err := readRelayPacket(conn, defaultRelayPacketLimit)
	if err != nil {
		t.Fatalf("read relay frame: %v", err)
	}
	return payload
}

// pinStreamWriter consumes one byte of a frame. net.Pipe writes block until
// every byte is read, so the writer is now deterministically stalled while the
// relay queue drains into the configured bound.
func pinStreamWriter(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var one [1]byte
	if _, err := io.ReadFull(conn, one[:]); err != nil {
		t.Fatalf("pin stream writer: %v", err)
	}
}

func TestStreamRelayQueueFullAndConcurrentEnqueue(t *testing.T) {
	const depth = 4
	const attempts = 64
	relay, server := newPipeStreamRelay(t, depth)

	if err := relay.Send([]byte("first-packet")); err != nil {
		t.Fatal(err)
	}
	if got := readPipeFrame(t, server); string(got) != "first-packet" {
		t.Fatalf("first frame = %q", got)
	}
	if err := relay.Send([]byte("pinned-packet")); err != nil {
		t.Fatal(err)
	}
	pinStreamWriter(t, server)

	var enqueued, backpressured, unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := relay.Send([]byte{byte(i)})
			switch {
			case err == nil:
				enqueued.Add(1)
			case IsRelayBackpressure(err):
				backpressured.Add(1)
			default:
				unexpected.Add(1)
				t.Errorf("stream send %d error = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("unexpected send errors = %d", unexpected.Load())
	}
	if enqueued.Load() != depth || backpressured.Load() != attempts-depth {
		t.Fatalf("enqueued = %d, backpressured = %d", enqueued.Load(), backpressured.Load())
	}
	want := RelayStats{
		Enqueued:           2 + depth,
		DroppedQueueFull:   attempts - depth,
		BackpressureEvents: attempts - depth,
		QueueDepth:         depth,
		QueueCapacity:      depth,
	}
	stats := relay.Stats()
	if stats.Enqueued != want.Enqueued ||
		stats.DroppedQueueFull != want.DroppedQueueFull ||
		stats.BackpressureEvents != want.BackpressureEvents ||
		stats.QueueDepth != want.QueueDepth ||
		stats.QueueCapacity != want.QueueCapacity {
		t.Fatalf("stream stats = %+v, want %+v", stats, want)
	}
}

func TestStreamRelayWriteErrorIsSavedAndCloses(t *testing.T) {
	relay, server := newPipeStreamRelay(t, 2)
	if err := relay.Send([]byte("will-fail")); err != nil {
		t.Fatal(err)
	}
	pinStreamWriter(t, server)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relay.writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not stop after a write error")
	}
	if err := relay.WriteError(); err == nil {
		t.Fatal("write error was not saved")
	}
	if err := relay.Send([]byte("after-error")); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("send after write error = %v, want ErrRelayClosed", err)
	}
	if stats := relay.Stats(); stats.WriteErrors != 1 {
		t.Fatalf("write error count = %d, want 1", stats.WriteErrors)
	}
	_ = relay.Close()
}

func TestStreamRelayCloseIsIdempotentAndStopsWriter(t *testing.T) {
	relay, _ := newPipeStreamRelay(t, 2)
	if err := relay.Send([]byte("queued-before-close")); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- relay.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked while the writer was stalled")
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	select {
	case <-relay.writerDone:
	default:
		t.Fatal("writer still running after Close")
	}
	if err := relay.Send([]byte("after-close")); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("send after Close = %v, want ErrRelayClosed", err)
	}

	var zero StreamRelay
	if err := zero.Close(); err != nil {
		t.Fatalf("zero-value Close = %v", err)
	}
	if err := zero.Send([]byte("x")); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("zero-value Send = %v, want ErrRelayClosed", err)
	}
}

func TestStreamRelayReceivePacketKeepsLengthFrame(t *testing.T) {
	relay, server := newPipeStreamRelay(t, 2)
	payload := []byte("compat-frame")
	go func() {
		_ = writeRelayPacket(server, payload, defaultRelayPacketLimit)
	}()
	_ = relay.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := relay.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}
}
func TestQueueDepthIsConfigurableAcrossStreamRelays(t *testing.T) {
	broker := NewRelayBrokerWithLimits(RelayLimits{QueueDepth: 37})
	if got := broker.QueueDepth(); got != 37 {
		t.Fatalf("QueueDepth() = %d, want 37", got)
	}
}
