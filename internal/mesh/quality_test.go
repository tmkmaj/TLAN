package mesh

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/network"
)

func TestQualityHistoryKeepsNewestAndDropsExpired(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	history := NewQualityHistoryWithClock(3, 5*time.Minute, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		history.Record(QualitySample{At: now.Add(time.Duration(i) * time.Second), Path: "direct UDP", RTTMillis: int64(20 + i)})
	}
	snapshot := history.Snapshot()
	if len(snapshot) != 3 {
		t.Fatalf("capacity snapshot len=%d want 3", len(snapshot))
	}
	if snapshot[0].RTTMillis != 22 || snapshot[2].RTTMillis != 24 {
		t.Fatalf("snapshot order/content=%+v", snapshot)
	}
	now = now.Add(10 * time.Minute)
	history.Record(QualitySample{At: now, Path: "relay TCP/TLS", RTTMillis: 80})
	snapshot = history.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Path != "relay TCP/TLS" {
		t.Fatalf("expired samples retained: %+v", snapshot)
	}
}

func TestQualityHistorySnapshotIsIndependent(t *testing.T) {
	history := NewQualityHistory(4)
	history.Record(QualitySample{At: time.Now(), Path: "direct UDP"})
	snapshot := history.Snapshot()
	snapshot[0].Path = "mutated"
	if history.Snapshot()[0].Path != "direct UDP" {
		t.Fatal("Snapshot must return an independent copy")
	}
}

func TestQualitySummary(t *testing.T) {
	start := time.Now().Add(-3 * time.Second)
	history := NewQualityHistory(10)
	history.Record(QualitySample{At: start, Path: "direct UDP", RTTMillis: 20, ReachablePeers: 2, TotalPeers: 2, Dropped: 1})
	history.Record(QualitySample{At: start.Add(time.Second), Path: "direct UDP", RTTMillis: 40, ReachablePeers: 1, TotalPeers: 2, Dropped: 4})
	history.Record(QualitySample{At: start.Add(2 * time.Second), Path: "relay TCP/TLS", RTTMillis: 100, ReachablePeers: 1, TotalPeers: 2, Dropped: 5})
	summary := history.Summary()
	if summary.Samples != 3 || summary.AverageRTTMillis != 53 || summary.MaxRTTMillis != 100 {
		t.Fatalf("summary=%+v", summary)
	}
	if summary.DirectSamples != 2 || summary.RelaySamples != 1 || summary.DroppedDelta != 4 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestQualityHistoryConcurrentRecordAndSnapshot(t *testing.T) {
	history := NewQualityHistory(300)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				history.Record(QualitySample{At: time.Now(), Path: "direct UDP", RTTMillis: int64(worker + i)})
				_ = history.Snapshot()
			}
		}(worker)
	}
	wg.Wait()
	if got := len(history.Snapshot()); got != 300 {
		t.Fatalf("snapshot len=%d want 300", got)
	}
}
func TestQualitySampleFromStatusAggregatesPathAndRTT(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	status := Status{
		Peers: []PeerStatus{
			{Reachable: true, Path: "direct UDP", RTT: 20 * time.Millisecond},
			{Reachable: true, Path: "direct UDP", RTT: 40 * time.Millisecond},
			{Reachable: false, Path: "checking"},
		},
		Sent: 100, Received: 90, Dropped: 2,
	}
	sample := qualitySampleFromStatus(at, status, 3, 64, 7, 2)
	if sample.At != at || sample.Path != "direct UDP" || sample.RTTMillis != 30 {
		t.Fatalf("sample=%+v", sample)
	}
	if sample.ReachablePeers != 2 || sample.TotalPeers != 3 || sample.RelayQueueDepth != 3 || sample.RelayQueueCapacity != 64 {
		t.Fatalf("sample=%+v", sample)
	}
	if sample.Sent != 100 || sample.Received != 90 || sample.Dropped != 2 || sample.RelayDrops != 7 || sample.RelayBackpressure != 2 {
		t.Fatalf("sample counters=%+v", sample)
	}
}
func TestQueueReplicaUsesBoundedQueueAndCountsOverflow(t *testing.T) {
	relay := new(network.StreamRelay)
	var drops int
	bind := &meshBind{replica: make(chan replicaDatagram, 1)}
	bind.onDrop = func() { drops++ }
	bind.queueReplica(relay, []byte("first"))
	bind.queueReplica(relay, []byte("second"))
	if got := len(bind.replica); got != 1 {
		t.Fatalf("replication queue depth=%d, want 1", got)
	}
	if drops != 1 {
		t.Fatalf("replication overflow drops=%d, want 1", drops)
	}
}
func TestBindReplicatesOnlySmallPacketsOnDirectPath(t *testing.T) {
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	peer := netip.MustParseAddr("10.240.0.3")
	bind := &meshBind{
		udp: sender, routes: make(map[netip.Addr]*peerRoute),
		replicateSmallPackets: true, replicationThreshold: 8,
		replica: make(chan replicaDatagram, 2),
	}
	bind.routes[peer] = &peerRoute{
		direct: receiver.LocalAddr().(*net.UDPAddr).AddrPort(), directSocket: 0,
		lastDirect: time.Now(), rtt: 10 * time.Millisecond, relay: new(network.StreamRelay),
	}
	endpoint := &endpoint{address: netip.AddrPortFrom(peer, 1)}
	if err := bind.Send([][]byte{[]byte("small")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("this packet is large")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if got := len(bind.replica); got != 1 {
		t.Fatalf("replicated packet count=%d, want 1", got)
	}
	if got := (<-bind.replica).data; string(got) != "small" {
		t.Fatalf("replicated payload=%q, want small", got)
	}
}
func TestQualityHistoryReturnsInsertionOrderWhenClockMovesBackwards(t *testing.T) {
	current := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	history := NewQualityHistoryWithClock(4, 5*time.Minute, func() time.Time { return current })
	history.Record(QualitySample{At: current, Path: "first"})
	current = current.Add(-time.Minute)
	history.Record(QualitySample{At: current, Path: "second"})
	got := history.Snapshot()
	if len(got) != 2 || got[0].Path != "first" || got[1].Path != "second" {
		t.Fatalf("snapshot=%+v", got)
	}
}
func TestQualityHistoryExpiresBoundedByCapacity(t *testing.T) {
	current := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	history := NewQualityHistoryWithClock(3, 5*time.Minute, func() time.Time { return current })
	history.Record(QualitySample{At: current.Add(-4 * time.Minute), Path: "old"})
	history.Record(QualitySample{At: current.Add(-3 * time.Minute), Path: "middle"})
	history.Record(QualitySample{At: current.Add(-2 * time.Minute), Path: "new"})
	current = current.Add(2 * time.Minute)
	got := history.Snapshot()
	if len(got) != 2 || got[0].Path != "middle" || got[1].Path != "new" {
		t.Fatalf("snapshot=%+v", got)
	}
}
