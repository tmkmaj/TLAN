// Package metrics implements a small, dependency-free Prometheus text-format
// registry used by the LAN mesh server.
//
// The package mirrors a subset of client_golang so the server can swap to the
// upstream library later: counters and gauges are goroutine-safe float64
// values, vector metrics are updated through their label value tuple, and a
// Registry renders a stable, sorted text exposition.
package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Sentinel errors returned by registration and exposition helpers. They are
// wrapped with the offending name, so callers should match them with
// errors.Is instead of comparing with ==.
var (
	ErrInvalidMetricName        = errors.New("metrics: invalid metric name")
	ErrDuplicateMetricName      = errors.New("metrics: duplicate metric name")
	ErrInvalidLabelName         = errors.New("metrics: invalid label name")
	ErrDuplicateLabelName       = errors.New("metrics: duplicate label name")
	ErrLabelCardinalityMismatch = errors.New("metrics: label value count does not match label names")
	ErrNilWriter                = errors.New("metrics: nil writer")
)

// Metric type strings used in the "# TYPE" line.
const (
	typeCounter = "counter"
	typeGauge   = "gauge"
)

// atomicFloat is a float64 that can be updated and read from multiple
// goroutines without locks. The float bit pattern is stored in an atomic word
// and updates retry with compare-and-swap on contention.
type atomicFloat struct {
	bits atomic.Uint64
}

func (v *atomicFloat) add(delta float64) {
	for {
		old := v.bits.Load()
		next := math.Float64frombits(old) + delta
		if v.bits.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

func (v *atomicFloat) set(value float64) {
	v.bits.Store(math.Float64bits(value))
}

func (v *atomicFloat) load() float64 {
	return math.Float64frombits(v.bits.Load())
}

// metricValue is the value surface shared by Counter and Gauge so a family
// can hold either kind.
type metricValue interface {
	Load() float64
}

// Counter is a single float64 series that follows counter semantics. The zero
// value is ready to use, and all methods are safe for concurrent use.
type Counter struct {
	val atomicFloat
}

// Inc increments the counter by 1.
func (c *Counter) Inc() { c.val.add(1) }

// Add adds delta to the counter.
func (c *Counter) Add(delta float64) { c.val.add(delta) }

// Set replaces the counter value, e.g. when restoring a persisted value.
func (c *Counter) Set(value float64) { c.val.set(value) }

// Load returns the current counter value.
func (c *Counter) Load() float64 { return c.val.load() }

// Gauge is a single float64 series that follows gauge semantics. The zero
// value is ready to use, and all methods are safe for concurrent use.
type Gauge struct {
	val atomicFloat
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() { g.val.add(1) }

// Add adds delta (which may be negative) to the gauge.
func (g *Gauge) Add(delta float64) { g.val.add(delta) }

// Set replaces the gauge value.
func (g *Gauge) Set(value float64) { g.val.set(value) }

// Load returns the current gauge value.
func (g *Gauge) Load() float64 { return g.val.load() }

// CounterVec is a set of counters that share a metric name and a fixed set of
// label names, updated through their label value tuple.
type CounterVec struct {
	f *family
}

// WithLabelValues returns the counter for the given label values, creating it
// on first use. The number of values must match the label names passed to
// NewCounterVec.
func (v *CounterVec) WithLabelValues(values ...string) (*Counter, error) {
	metric, err := v.f.withLabelValues(values)
	if err != nil {
		return nil, err
	}
	return metric.(*Counter), nil
}

// GaugeVec is a set of gauges that share a metric name and a fixed set of
// label names, updated through their label value tuple.
type GaugeVec struct {
	f *family
}

// WithLabelValues returns the gauge for the given label values, creating it
// on first use. The number of values must match the label names passed to
// NewGaugeVec.
func (v *GaugeVec) WithLabelValues(values ...string) (*Gauge, error) {
	metric, err := v.f.withLabelValues(values)
	if err != nil {
		return nil, err
	}
	return metric.(*Gauge), nil
}

// series is one label value tuple of a family together with its value.
type series struct {
	labelValues []string
	value       metricValue
}

// family is one registered metric name with its metadata and series set.
type family struct {
	name   string
	help   string
	typ    string
	labels []string // label names in exposition order; empty for simple metrics

	mu     sync.Mutex
	series map[string]*series
}

// withLabelValues returns the metric for values, creating it on first use.
func (f *family) withLabelValues(values []string) (metricValue, error) {
	if len(values) != len(f.labels) {
		return nil, fmt.Errorf("%w: %q expects %d label value(s), got %d",
			ErrLabelCardinalityMismatch, f.name, len(f.labels), len(values))
	}
	key := encodeLabelValues(values)
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.series[key]; ok {
		return s.value, nil
	}
	var metric metricValue
	switch f.typ {
	case typeCounter:
		metric = new(Counter)
	case typeGauge:
		metric = new(Gauge)
	}
	owned := make([]string, len(values))
	copy(owned, values)
	f.series[key] = &series{labelValues: owned, value: metric}
	return metric, nil
}

// expose writes the HELP/TYPE preamble and all series of f, ordered by label
// values so the output does not depend on map iteration order.
func (f *family) expose(buf *bytes.Buffer) {
	buf.WriteString("# HELP ")
	buf.WriteString(f.name)
	buf.WriteByte(' ')
	buf.WriteString(escapeHelp(f.help))
	buf.WriteByte('\n')
	buf.WriteString("# TYPE ")
	buf.WriteString(f.name)
	buf.WriteByte(' ')
	buf.WriteString(f.typ)
	buf.WriteByte('\n')

	f.mu.Lock()
	series := make([]*series, 0, len(f.series))
	for _, s := range f.series {
		series = append(series, s)
	}
	f.mu.Unlock()

	sort.Slice(series, func(i, j int) bool {
		return compareLabelValues(series[i].labelValues, series[j].labelValues) < 0
	})

	for _, s := range series {
		buf.WriteString(f.name)
		if len(f.labels) > 0 {
			buf.WriteByte('{')
			for i, label := range f.labels {
				if i > 0 {
					buf.WriteByte(',')
				}
				buf.WriteString(label)
				buf.WriteString(`="`)
				buf.WriteString(escapeLabelValue(s.labelValues[i]))
				buf.WriteByte('"')
			}
			buf.WriteByte('}')
		}
		buf.WriteByte(' ')
		buf.WriteString(strconv.FormatFloat(s.value.Load(), 'g', -1, 64))
		buf.WriteByte('\n')
	}
}

// Registry owns metric families and renders them in the Prometheus text
// exposition format. It is safe for concurrent use and its zero value is a
// valid, empty registry.
type Registry struct {
	mu   sync.Mutex
	fams map[string]*family
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// NewCounter registers and returns a counter with a single, label-free series.
// It returns ErrInvalidMetricName or ErrDuplicateMetricName on bad input.
func (r *Registry) NewCounter(name, help string) (*Counter, error) {
	f, err := r.register(name, help, typeCounter, nil)
	if err != nil {
		return nil, err
	}
	metric, err := f.withLabelValues(nil)
	if err != nil {
		return nil, err
	}
	return metric.(*Counter), nil
}

// NewGauge registers and returns a gauge with a single, label-free series.
// It returns ErrInvalidMetricName or ErrDuplicateMetricName on bad input.
func (r *Registry) NewGauge(name, help string) (*Gauge, error) {
	f, err := r.register(name, help, typeGauge, nil)
	if err != nil {
		return nil, err
	}
	metric, err := f.withLabelValues(nil)
	if err != nil {
		return nil, err
	}
	return metric.(*Gauge), nil
}

// NewCounterVec registers and returns a counter vector with the given label
// names. Label names must be unique and valid, the metric name valid, or a
// sentinel error is returned.
func (r *Registry) NewCounterVec(name, help string, labels []string) (*CounterVec, error) {
	f, err := r.register(name, help, typeCounter, labels)
	if err != nil {
		return nil, err
	}
	return &CounterVec{f: f}, nil
}

// NewGaugeVec registers and returns a gauge vector with the given label names.
// Label names must be unique and valid, the metric name valid, or a sentinel
// error is returned.
func (r *Registry) NewGaugeVec(name, help string, labels []string) (*GaugeVec, error) {
	f, err := r.register(name, help, typeGauge, labels)
	if err != nil {
		return nil, err
	}
	return &GaugeVec{f: f}, nil
}

// WritePrometheus writes every registered family in the Prometheus text
// exposition format. Families are ordered by metric name and series by label
// values, so repeated calls over unchanged data produce identical bytes.
// A nil writer is reported as ErrNilWriter and a short write as
// io.ErrShortWrite.
func (r *Registry) WritePrometheus(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}

	r.mu.Lock()
	ordered := make([]*family, 0, len(r.fams))
	for _, f := range r.fams {
		ordered = append(ordered, f)
	}
	r.mu.Unlock()
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })

	var buf bytes.Buffer
	for _, f := range ordered {
		f.expose(&buf)
	}

	data := buf.Bytes()
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n < len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// register validates and adds a metric family. Validation happens before the
// family is stored, so a rejected registration never reserves the name.
func (r *Registry) register(name, help, typ string, labels []string) (*family, error) {
	if !validMetricName(name) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMetricName, name)
	}
	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if !validLabelName(label) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidLabelName, label)
		}
		if _, dup := seen[label]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateLabelName, label)
		}
		seen[label] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.fams[name]; dup {
		return nil, fmt.Errorf("%w: %q", ErrDuplicateMetricName, name)
	}
	if r.fams == nil {
		r.fams = make(map[string]*family)
	}
	f := &family{
		name:   name,
		help:   help,
		typ:    typ,
		labels: append([]string(nil), labels...),
		series: make(map[string]*series),
	}
	r.fams[name] = f
	return f, nil
}

// encodeLabelValues builds a collision-free map key for a label value tuple by
// length-prefixing every value; plain concatenation would confuse ("a", "bc")
// with ("ab", "c").
func encodeLabelValues(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

// compareLabelValues orders label value tuples element-wise so series order
// depends only on the values, not on map iteration order.
func compareLabelValues(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return len(a) - len(b)
}

var (
	helpEscaper       = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
)

// escapeHelp escapes HELP text as required by the text exposition format:
// backslashes and line feeds.
func escapeHelp(text string) string {
	return helpEscaper.Replace(text)
}

// escapeLabelValue escapes a label value as required by the text exposition
// format: backslashes, double quotes and line feeds.
func escapeLabelValue(value string) string {
	return labelValueEscaper.Replace(value)
}

// validMetricName reports whether name matches [a-zA-Z_:][a-zA-Z0-9_:]*.
func validMetricName(name string) bool {
	if name == "" || !isMetricNameByte(name[0], true) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isMetricNameByte(name[i], false) {
			return false
		}
	}
	return true
}

func isMetricNameByte(c byte, first bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == ':':
		return true
	case c >= '0' && c <= '9':
		return !first
	}
	return false
}

// validLabelName reports whether name matches [a-zA-Z_][a-zA-Z0-9_]*.
func validLabelName(name string) bool {
	if name == "" || !isLabelNameByte(name[0], true) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isLabelNameByte(name[i], false) {
			return false
		}
	}
	return true
}

func isLabelNameByte(c byte, first bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		return true
	case c >= '0' && c <= '9':
		return !first
	}
	return false
}
