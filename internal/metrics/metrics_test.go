package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestCounterAndGaugeConcurrentUpdates(t *testing.T) {
	var counter Counter
	var gauge Gauge

	const workers = 8
	const iterations = 1000
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				counter.Inc()
				gauge.Add(2)
			}
		}()
	}
	wg.Wait()

	if got, want := counter.Load(), float64(workers*iterations); got != want {
		t.Fatalf("counter.Load() = %v, want %v", got, want)
	}
	if got, want := gauge.Load(), float64(2*workers*iterations); got != want {
		t.Fatalf("gauge.Load() = %v, want %v", got, want)
	}

	counter.Set(7)
	counter.Add(3)
	if got := counter.Load(); got != 10 {
		t.Fatalf("counter after Set/Add = %v, want 10", got)
	}

	gauge.Set(-4.5)
	gauge.Inc()
	if got := gauge.Load(); got != -3.5 {
		t.Fatalf("gauge after Set/Inc = %v, want -3.5", got)
	}
}

func TestRegistryWritesStablePrometheusOutput(t *testing.T) {
	reg := NewRegistry()
	requests := mustCounter(t, reg, "radmin_requests_total", "Total requests.")
	requests.Add(3)
	peers := mustGauge(t, reg, "radmin_active_peers", "Active peers.")
	peers.Set(2)
	bytesVec := mustCounterVec(t, reg, "radmin_bytes_total", "Network bytes.", []string{"direction", "peer"})

	out, err := bytesVec.WithLabelValues("out", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	out.Add(20)
	inA, err := bytesVec.WithLabelValues("in", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	inA.Add(10)
	inB, err := bytesVec.WithLabelValues("in", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	inB.Add(5)

	want := `# HELP radmin_active_peers Active peers.
# TYPE radmin_active_peers gauge
radmin_active_peers 2
# HELP radmin_bytes_total Network bytes.
# TYPE radmin_bytes_total counter
radmin_bytes_total{direction="in",peer="10.0.0.1"} 5
radmin_bytes_total{direction="in",peer="10.0.0.2"} 10
radmin_bytes_total{direction="out",peer="10.0.0.2"} 20
# HELP radmin_requests_total Total requests.
# TYPE radmin_requests_total counter
radmin_requests_total 3
`

	first := writeRegistry(t, reg)
	if first != want {
		t.Fatalf("unexpected exposition:\n--- got ---\n%s--- want ---\n%s", first, want)
	}
	for i := 0; i < 10; i++ {
		if got := writeRegistry(t, reg); got != first {
			t.Fatalf("exposition changed between calls:\n--- first ---\n%s--- got ---\n%s", first, got)
		}
	}
}

func TestPrometheusHelpAndLabelEscaping(t *testing.T) {
	reg := NewRegistry()
	vec := mustCounterVec(t, reg, "radmin_escaped_total", "line one\npath C:\\tmp\\metrics", []string{"zone", "note"})

	first, err := vec.WithLabelValues(`a\b"c`, "first\nsecond")
	if err != nil {
		t.Fatal(err)
	}
	first.Inc()
	second, err := vec.WithLabelValues("plain", `quote " and slash \`)
	if err != nil {
		t.Fatal(err)
	}
	second.Add(2)

	want := `# HELP radmin_escaped_total line one\npath C:\\tmp\\metrics
# TYPE radmin_escaped_total counter
radmin_escaped_total{zone="a\\b\"c",note="first\nsecond"} 1
radmin_escaped_total{zone="plain",note="quote \" and slash \\"} 2
`
	if got := writeRegistry(t, reg); got != want {
		t.Fatalf("unexpected escaped exposition:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestInvalidNamesAndDuplicateRegistrationReturnErrors(t *testing.T) {
	reg := NewRegistry()

	invalidMetricNames := []string{"", "9starts_with_digit", "has-dash", "has space", "has.dot", "gauge{label"}
	for i, name := range invalidMetricNames {
		name := name
		t.Run(fmt.Sprintf("metric_%d", i), func(t *testing.T) {
			if _, err := reg.NewCounter(name, "help"); !errors.Is(err, ErrInvalidMetricName) {
				t.Fatalf("NewCounter(%q) error = %v, want ErrInvalidMetricName", name, err)
			}
		})
	}

	if _, err := reg.NewCounter("http:requests_total", "colons are valid in metric names"); err != nil {
		t.Fatalf("valid metric name rejected: %v", err)
	}

	if _, err := reg.NewCounter("duplicate_total", "first"); err != nil {
		t.Fatalf("initial registration failed: %v", err)
	}
	if _, err := reg.NewGauge("duplicate_total", "second"); !errors.Is(err, ErrDuplicateMetricName) {
		t.Fatalf("duplicate registration error = %v, want ErrDuplicateMetricName", err)
	}
	if _, err := reg.NewCounterVec("duplicate_total", "third", []string{"label"}); !errors.Is(err, ErrDuplicateMetricName) {
		t.Fatalf("duplicate vector registration error = %v, want ErrDuplicateMetricName", err)
	}

	invalidLabels := []struct {
		name   string
		labels []string
		want   error
	}{
		{name: "empty", labels: []string{""}, want: ErrInvalidLabelName},
		{name: "starts_with_digit", labels: []string{"9bad"}, want: ErrInvalidLabelName},
		{name: "dash", labels: []string{"bad-label"}, want: ErrInvalidLabelName},
		{name: "space", labels: []string{"has space"}, want: ErrInvalidLabelName},
		{name: "colon", labels: []string{"with:colon"}, want: ErrInvalidLabelName},
		{name: "duplicate", labels: []string{"ok", "ok"}, want: ErrDuplicateLabelName},
	}
	for _, tc := range invalidLabels {
		tc := tc
		t.Run("label_"+tc.name, func(t *testing.T) {
			if _, err := reg.NewGaugeVec("label_validation_total", "help", tc.labels); !errors.Is(err, tc.want) {
				t.Fatalf("NewGaugeVec(%v) error = %v, want %v", tc.labels, err, tc.want)
			}
		})
	}
	if _, err := reg.NewGauge("label_validation_total", "invalid vectors must not reserve the name"); err != nil {
		t.Fatalf("invalid vector left a registration behind: %v", err)
	}

	vec := mustCounterVec(t, reg, "cardinality_check_total", "help", []string{"a", "b"})
	if _, err := vec.WithLabelValues("one"); !errors.Is(err, ErrLabelCardinalityMismatch) {
		t.Fatalf("too few label values error = %v, want ErrLabelCardinalityMismatch", err)
	}
	if _, err := vec.WithLabelValues("one", "two", "three"); !errors.Is(err, ErrLabelCardinalityMismatch) {
		t.Fatalf("too many label values error = %v, want ErrLabelCardinalityMismatch", err)
	}
}

func TestLabelCardinalityAndStableOrdering(t *testing.T) {
	reg := NewRegistry()
	vec := mustGaugeVec(t, reg, "radmin_peer_latency_ms", "Peer latency.", []string{"region", "peer"})

	type key struct {
		region string
		peer   string
	}
	const seriesCount = 128
	values := make(map[key]float64, seriesCount)
	for i := 0; i < seriesCount; i++ {
		k := key{
			region: fmt.Sprintf("region-%02d", (i*37)%8),
			peer:   fmt.Sprintf("peer-%03d", i),
		}
		values[k] = float64(i + 1)
		metric, err := vec.WithLabelValues(k.region, k.peer)
		if err != nil {
			t.Fatalf("WithLabelValues(%q, %q): %v", k.region, k.peer, err)
		}
		metric.Set(values[k])
	}

	first := writeRegistry(t, reg)
	lines := sampleLines(first)
	if len(lines) != seriesCount {
		t.Fatalf("got %d series, want %d:\n%s", len(lines), seriesCount, first)
	}

	keys := make([]key, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].region != keys[j].region {
			return keys[i].region < keys[j].region
		}
		return keys[i].peer < keys[j].peer
	})
	for i, k := range keys {
		want := fmt.Sprintf(`radmin_peer_latency_ms{region=%q,peer=%q} %v`, k.region, k.peer, values[k])
		if lines[i] != want {
			t.Fatalf("series %d = %q, want %q", i, lines[i], want)
		}
	}

	if second := writeRegistry(t, reg); second != first {
		t.Fatalf("cardinality output is not stable:\n--- first ---\n%s--- second ---\n%s", first, second)
	}
}

func TestVecConcurrentSeriesCreationAndUpdates(t *testing.T) {
	reg := NewRegistry()
	vec := mustCounterVec(t, reg, "radmin_jobs_total", "Jobs processed.", []string{"worker"})

	const workers = 16
	const iterations = 250
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			shared, err := vec.WithLabelValues("shared")
			if err != nil {
				errCh <- err
				return
			}
			own, err := vec.WithLabelValues(fmt.Sprintf("worker-%02d", i))
			if err != nil {
				errCh <- err
				return
			}
			for j := 0; j < iterations; j++ {
				shared.Inc()
				own.Inc()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	shared, err := vec.WithLabelValues("shared")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := shared.Load(), float64(workers*iterations); got != want {
		t.Fatalf("shared series = %v, want %v", got, want)
	}
	for i := 0; i < workers; i++ {
		own, err := vec.WithLabelValues(fmt.Sprintf("worker-%02d", i))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := own.Load(), float64(iterations); got != want {
			t.Fatalf("worker %d = %v, want %v", i, got, want)
		}
	}

	if lines := sampleLines(writeRegistry(t, reg)); len(lines) != workers+1 {
		t.Fatalf("got %d series, want %d", len(lines), workers+1)
	}
}

func TestWritePrometheusReportsWriterFailures(t *testing.T) {
	reg := NewRegistry()
	mustGauge(t, reg, "writer_check", "help").Set(1)

	if err := reg.WritePrometheus(errorWriter{}); !errors.Is(err, errWriteFailed) {
		t.Fatalf("writer error = %v, want %v", err, errWriteFailed)
	}
	if err := reg.WritePrometheus(shortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want io.ErrShortWrite", err)
	}
	if err := reg.WritePrometheus(nil); !errors.Is(err, ErrNilWriter) {
		t.Fatalf("nil writer error = %v, want ErrNilWriter", err)
	}
}

func TestZeroValueRegistryWritesNothing(t *testing.T) {
	var reg Registry
	if got := writeRegistry(t, &reg); got != "" {
		t.Fatalf("zero-value registry output = %q, want empty", got)
	}
	if _, err := reg.NewGauge("zero_value_gauge", "help"); err != nil {
		t.Fatalf("zero-value registry registration failed: %v", err)
	}
}

func mustCounter(t *testing.T, reg *Registry, name, help string) *Counter {
	t.Helper()
	c, err := reg.NewCounter(name, help)
	if err != nil {
		t.Fatalf("NewCounter(%q): %v", name, err)
	}
	return c
}

func mustGauge(t *testing.T, reg *Registry, name, help string) *Gauge {
	t.Helper()
	g, err := reg.NewGauge(name, help)
	if err != nil {
		t.Fatalf("NewGauge(%q): %v", name, err)
	}
	return g
}

func mustCounterVec(t *testing.T, reg *Registry, name, help string, labels []string) *CounterVec {
	t.Helper()
	v, err := reg.NewCounterVec(name, help, labels)
	if err != nil {
		t.Fatalf("NewCounterVec(%q): %v", name, err)
	}
	return v
}

func mustGaugeVec(t *testing.T, reg *Registry, name, help string, labels []string) *GaugeVec {
	t.Helper()
	v, err := reg.NewGaugeVec(name, help, labels)
	if err != nil {
		t.Fatalf("NewGaugeVec(%q): %v", name, err)
	}
	return v
}

func writeRegistry(t *testing.T, reg *Registry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	return buf.String()
}

func sampleLines(exposition string) []string {
	var lines []string
	for _, line := range strings.Split(exposition, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

var errWriteFailed = errors.New("write failed")

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}
