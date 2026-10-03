package observability

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics is the process metric registry.
//
// It exposes the Prometheus text exposition format directly rather than
// depending on a client library. The format is a stable, documented contract
// consumed by Prometheus, OpenTelemetry's prometheus receiver, Datadog's
// OpenMetrics check, Grafana Alloy and every other scraper in use; implementing
// the ~40 lines that render it keeps the dependency surface of a server that
// handles customer data as small as it can be.
//
// Cardinality is bounded by construction: every label value comes from a closed
// set defined in this repository (a registered tool name, a domain error code,
// an MCP method), never from a request argument. That is what stops a caller
// from turning a metric into unbounded memory growth.
type Metrics struct {
	enabled bool

	mu sync.RWMutex
	// counters and histograms are keyed by name plus rendered labels.
	counters   map[string]*counter
	histograms map[string]*histogram
	gauges     map[string]*gaugeFn

	startedAt time.Time
}

type counter struct {
	name   string
	labels []label
	help   string
	value  atomic.Int64
}

type histogram struct {
	name   string
	labels []label
	help   string

	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	total   uint64
}

type gaugeFn struct {
	name   string
	labels []label
	help   string
	read   func() float64
}

type label struct{ name, value string }

// latencyBuckets are seconds, chosen to straddle the interesting range for an
// MCP server: sub-millisecond in-process work at one end, a backend call that
// has hit its timeout at the other.
var latencyBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// sizeBuckets are bytes. The interesting question for a payload histogram is
// how close responses run to the configured response cap, so the buckets climb
// to a few megabytes rather than stopping at a typical record.
var sizeBuckets = []float64{
	256, 1024, 4096, 16384, 65536, 262144, 1 << 20, 4 << 20,
}

// bucketsFor picks the bucket boundaries appropriate to a metric.
func bucketsFor(name string) []float64 {
	if name == ResponseBytes {
		return sizeBuckets
	}
	return latencyBuckets
}

// NewMetrics returns a registry. A disabled registry costs an atomic load per
// observation and allocates nothing.
func NewMetrics(enabled bool) *Metrics {
	return &Metrics{
		enabled:    enabled,
		counters:   map[string]*counter{},
		histograms: map[string]*histogram{},
		gauges:     map[string]*gaugeFn{},
		startedAt:  time.Now(),
	}
}

// Enabled reports whether metrics are being collected.
func (m *Metrics) Enabled() bool { return m != nil && m.enabled }

// Inc adds one to a counter.
func (m *Metrics) Inc(name string, labels ...string) { m.Add(name, 1, labels...) }

// Add adds delta to a counter. labels are alternating name/value pairs.
func (m *Metrics) Add(name string, delta int64, labels ...string) {
	if !m.Enabled() {
		return
	}
	c := m.counter(name, labels)
	c.value.Add(delta)
}

// Observe records a duration in a histogram.
func (m *Metrics) Observe(name string, d time.Duration, labels ...string) {
	if !m.Enabled() {
		return
	}
	m.histogram(name, labels).observe(d.Seconds())
}

// ObserveValue records a bare numeric observation, such as a payload size.
func (m *Metrics) ObserveValue(name string, v float64, labels ...string) {
	if !m.Enabled() {
		return
	}
	m.histogram(name, labels).observe(v)
}

// SetGauge registers a callback read at scrape time.
//
// A callback rather than a stored value, because the interesting gauges - open
// sessions, circuit-breaker state - are owned by the component that knows them,
// and a push model would have that component racing the scraper.
func (m *Metrics) SetGauge(name, help string, read func() float64, labels ...string) {
	if !m.Enabled() {
		return
	}
	key := key(name, labels)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[key] = &gaugeFn{name: name, labels: pairs(labels), help: help, read: read}
}

func (m *Metrics) counter(name string, labels []string) *counter {
	k := key(name, labels)
	m.mu.RLock()
	c, ok := m.counters[k]
	m.mu.RUnlock()
	if ok {
		return c
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.counters[k]; ok {
		return c
	}
	c = &counter{name: name, labels: pairs(labels), help: helpFor(name)}
	m.counters[k] = c
	return c
}

func (m *Metrics) histogram(name string, labels []string) *histogram {
	k := key(name, labels)
	m.mu.RLock()
	h, ok := m.histograms[k]
	m.mu.RUnlock()
	if ok {
		return h
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.histograms[k]; ok {
		return h
	}
	bounds := bucketsFor(name)
	h = &histogram{
		name:    name,
		labels:  pairs(labels),
		help:    helpFor(name),
		buckets: bounds,
		counts:  make([]uint64, len(bounds)),
	}
	m.histograms[k] = h
	return h
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

// Handler serves the metric registry in Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(m.Render()))
	})
}

// Render produces the exposition text.
func (m *Metrics) Render() string {
	if !m.Enabled() {
		return "# metrics are disabled\n"
	}

	m.mu.RLock()
	counters := make([]*counter, 0, len(m.counters))
	for _, c := range m.counters {
		counters = append(counters, c)
	}
	histograms := make([]*histogram, 0, len(m.histograms))
	for _, h := range m.histograms {
		histograms = append(histograms, h)
	}
	gauges := make([]*gaugeFn, 0, len(m.gauges))
	for _, g := range m.gauges {
		gauges = append(gauges, g)
	}
	m.mu.RUnlock()

	var b strings.Builder

	// Group by metric name so each HELP/TYPE pair is emitted once, which the
	// exposition format requires.
	byName := map[string][]*counter{}
	for _, c := range counters {
		byName[c.name] = append(byName[c.name], c)
	}
	for _, name := range sortedKeys(byName) {
		series := byName[name]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, series[0].help, name)
		sortSeries(series, func(c *counter) string { return renderLabels(c.labels) })
		for _, c := range series {
			fmt.Fprintf(&b, "%s%s %d\n", name, renderLabels(c.labels), c.value.Load())
		}
	}

	gaugesByName := map[string][]*gaugeFn{}
	for _, g := range gauges {
		gaugesByName[g.name] = append(gaugesByName[g.name], g)
	}
	for _, name := range sortedKeys(gaugesByName) {
		series := gaugesByName[name]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, series[0].help, name)
		sortSeries(series, func(g *gaugeFn) string { return renderLabels(g.labels) })
		for _, g := range series {
			fmt.Fprintf(&b, "%s%s %s\n", name, renderLabels(g.labels), formatFloat(g.read()))
		}
	}

	histByName := map[string][]*histogram{}
	for _, h := range histograms {
		histByName[h.name] = append(histByName[h.name], h)
	}
	for _, name := range sortedKeys(histByName) {
		series := histByName[name]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", name, series[0].help, name)
		sortSeries(series, func(h *histogram) string { return renderLabels(h.labels) })
		for _, h := range series {
			h.render(&b)
		}
	}

	fmt.Fprintf(&b, "# HELP mcp_uptime_seconds Seconds since the process started serving.\n# TYPE mcp_uptime_seconds gauge\nmcp_uptime_seconds %s\n",
		formatFloat(time.Since(m.startedAt).Seconds()))
	return b.String()
}

func (h *histogram) render(b *strings.Builder) {
	h.mu.Lock()
	counts := append([]uint64(nil), h.counts...)
	sum, total := h.sum, h.total
	h.mu.Unlock()

	for i, bound := range h.buckets {
		fmt.Fprintf(b, "%s_bucket%s %d\n", h.name,
			renderLabels(append(append([]label(nil), h.labels...), label{"le", formatFloat(bound)})), counts[i])
	}
	fmt.Fprintf(b, "%s_bucket%s %d\n", h.name,
		renderLabels(append(append([]label(nil), h.labels...), label{"le", "+Inf"})), total)
	fmt.Fprintf(b, "%s_sum%s %s\n", h.name, renderLabels(h.labels), formatFloat(sum))
	fmt.Fprintf(b, "%s_count%s %d\n", h.name, renderLabels(h.labels), total)
}

func key(name string, labels []string) string {
	if len(labels) == 0 {
		return name
	}
	return name + "\x00" + strings.Join(labels, "\x00")
}

func pairs(labels []string) []label {
	out := make([]label, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		out = append(out, label{name: labels[i], value: labels[i+1]})
	}
	return out
}

func renderLabels(ls []label) string {
	if len(ls) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		parts = append(parts, l.name+`="`+escape(l.value)+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// escape applies the exposition format's escaping rules to a label value.
func escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortSeries[T any](series []T, key func(T) string) {
	sort.SliceStable(series, func(i, j int) bool { return key(series[i]) < key(series[j]) })
}
