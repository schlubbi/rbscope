package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// OTLPConfig configures the OTLP exporter.
type OTLPConfig struct {
	// Endpoint is the OTLP HTTP endpoint (e.g. "http://localhost:4318").
	Endpoint   string
	ServiceName string
	FlushEvery time.Duration
	Logger     *slog.Logger
}

// OTLPExporter implements collector.Exporter by converting stack samples
// into OTLP trace spans and pushing them via HTTP/JSON to an OTLP collector
// (e.g. Jaeger).
type OTLPExporter struct {
	endpoint   string
	serviceName string
	log        *slog.Logger
	client     *http.Client
	flushEvery time.Duration

	mu      sync.Mutex
	samples []*collector.RubySampleEvent
	spans   []*collector.RubySpanEvent

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewOTLPExporter creates an exporter that pushes profiling spans via OTLP HTTP.
func NewOTLPExporter(cfg OTLPConfig) *OTLPExporter {
	if cfg.FlushEvery == 0 {
		cfg.FlushEvery = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "rbscope"
	}
	// Ensure endpoint doesn't have trailing path — we append /v1/traces ourselves.
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/v1/traces") {
		endpoint += "/v1/traces"
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &OTLPExporter{
		endpoint:    endpoint,
		serviceName: cfg.ServiceName,
		log:         cfg.Logger,
		client:      &http.Client{Timeout: 10 * time.Second},
		flushEvery:  cfg.FlushEvery,
		ctx:         ctx,
		cancel:      cancel,
	}

	e.wg.Add(1)
	go e.flushLoop()

	return e
}

// Export accumulates a sample or span event for the next flush.
func (e *OTLPExporter) Export(_ context.Context, event any) error {
	switch ev := event.(type) {
	case *collector.RubySampleEvent:
		e.mu.Lock()
		e.samples = append(e.samples, ev)
		e.mu.Unlock()
	case *collector.RubySpanEvent:
		e.mu.Lock()
		e.spans = append(e.spans, ev)
		e.mu.Unlock()
	}
	return nil
}

// Flush pushes accumulated samples and spans as OTLP trace data.
func (e *OTLPExporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	samples := e.samples
	e.samples = nil
	spans := e.spans
	e.spans = nil
	e.mu.Unlock()

	if len(samples) == 0 && len(spans) == 0 {
		return nil
	}

	payload := e.buildPayload(samples, spans)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal OTLP payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("OTLP push: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP push: HTTP %d", resp.StatusCode)
	}

	e.log.Info("pushed traces to OTLP", "samples", len(samples), "spans", len(spans), "endpoint", e.endpoint)
	return nil
}

// Close stops the flush loop and pushes remaining data.
func (e *OTLPExporter) Close() error {
	e.cancel()
	e.wg.Wait()
	return e.Flush(context.Background())
}

func (e *OTLPExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.Flush(e.ctx); err != nil {
				e.log.Warn("otlp flush failed", "err", err)
			}
		}
	}
}

// buildPayload constructs an OTLP ExportTraceServiceRequest JSON structure.
// Real RubySpanEvents become proper OTLP spans with trace_id/span_id.
// Profiling samples are grouped into summary spans per PID.
func (e *OTLPExporter) buildPayload(samples []*collector.RubySampleEvent, spans []*collector.RubySpanEvent) otlpTraceRequest {
	now := time.Now()
	flushStart := now.Add(-e.flushEvery)

	var allSpans []otlpSpan

	// 1. Convert real RubySpanEvents into proper OTLP spans
	for _, s := range spans {
		traceID := fmt.Sprintf("%032x", s.TraceID)
		spanID := fmt.Sprintf("%016x", s.SpanID)
		parentID := fmt.Sprintf("%016x", s.ParentID)

		kind := 1 // SPAN_KIND_INTERNAL
		name := "ruby.span"
		if s.Enter == 1 {
			name = "ruby.span.enter"
		}

		span := otlpSpan{
			TraceID:           traceID,
			SpanID:            spanID,
			ParentSpanID:      parentID,
			Name:              name,
			Kind:              kind,
			StartTimeUnixNano: fmt.Sprintf("%d", s.Timestamp),
			EndTimeUnixNano:   fmt.Sprintf("%d", s.Timestamp),
			Attributes: []otlpKeyValue{
				{Key: "pid", Value: otlpAnyValue{IntValue: intPtr(int64(s.PID))}},
				{Key: "tid", Value: otlpAnyValue{IntValue: intPtr(int64(s.TID))}},
				{Key: "profiler", Value: otlpAnyValue{StringValue: strPtr("rbscope")}},
			},
		}
		allSpans = append(allSpans, span)
	}

	// 2. Group profiling samples by PID into summary spans
	byPID := make(map[uint32][]*collector.RubySampleEvent)
	for _, s := range samples {
		byPID[s.PID] = append(byPID[s.PID], s)
	}

	for pid, pidSamples := range byPID {
		stackCounts := make(map[string]int)
		var spanEvents []otlpEvent

		for _, s := range pidSamples {
			frames := collector.ParseInlineStack(s.StackData)
			if len(frames) == 0 {
				continue
			}

			parts := make([]string, len(frames))
			for i, f := range frames {
				parts[i] = f.Label
			}
			collapsed := strings.Join(parts, ";")
			stackCounts[collapsed]++

			spanEvents = append(spanEvents, otlpEvent{
				Name:         "stack_sample",
				TimeUnixNano: fmt.Sprintf("%d", s.Timestamp),
				Attributes: []otlpKeyValue{
					{Key: "stack", Value: otlpAnyValue{StringValue: strPtr(collapsed)}},
					{Key: "tid", Value: otlpAnyValue{IntValue: intPtr(int64(s.TID))}},
				},
			})
		}

		topFunc := ""
		topCount := 0
		for stack, count := range stackCounts {
			if count > topCount {
				topCount = count
				if idx := strings.Index(stack, ";"); idx > 0 {
					topFunc = stack[:idx]
				} else {
					topFunc = stack
				}
			}
		}

		traceID := generateTraceID(pid, flushStart)
		spanID := generateSpanID(pid, flushStart)

		span := otlpSpan{
			TraceID:           traceID,
			SpanID:            spanID,
			Name:              fmt.Sprintf("rbscope.cpu.profile [pid:%d]", pid),
			Kind:              1,
			StartTimeUnixNano: fmt.Sprintf("%d", flushStart.UnixNano()),
			EndTimeUnixNano:   fmt.Sprintf("%d", now.UnixNano()),
			Events:            spanEvents,
			Attributes: []otlpKeyValue{
				{Key: "pid", Value: otlpAnyValue{IntValue: intPtr(int64(pid))}},
				{Key: "sample_count", Value: otlpAnyValue{IntValue: intPtr(int64(len(pidSamples)))}},
				{Key: "unique_stacks", Value: otlpAnyValue{IntValue: intPtr(int64(len(stackCounts)))}},
				{Key: "top_function", Value: otlpAnyValue{StringValue: strPtr(topFunc)}},
				{Key: "profiler", Value: otlpAnyValue{StringValue: strPtr("rbscope")}},
			},
		}
		allSpans = append(allSpans, span)
	}

	rs := otlpResourceSpan{
		Resource: otlpResource{
			Attributes: []otlpKeyValue{
				{Key: "service.name", Value: otlpAnyValue{StringValue: strPtr(e.serviceName)}},
			},
		},
		ScopeSpans: []otlpScopeSpan{
			{
				Scope: otlpScope{Name: "rbscope-collector", Version: "0.1.0"},
				Spans: allSpans,
			},
		},
	}

	return otlpTraceRequest{ResourceSpans: []otlpResourceSpan{rs}}
}

// generateTraceID creates a deterministic trace ID from PID and time.
func generateTraceID(pid uint32, t time.Time) string {
	h := uint64(14695981039346656037)
	h ^= uint64(pid)
	h *= 1099511628211
	h ^= uint64(t.UnixNano())
	h *= 1099511628211
	return fmt.Sprintf("%016x%016x", h, uint64(t.UnixNano()))
}

// generateSpanID creates a deterministic span ID from PID and time.
func generateSpanID(pid uint32, t time.Time) string {
	h := uint64(14695981039346656037)
	h ^= uint64(pid)
	h *= 1099511628211
	h ^= uint64(t.UnixNano()) >> 1
	h *= 1099511628211
	return fmt.Sprintf("%016x", h)
}

func strPtr(s string) *string { return &s }
func intPtr(i int64) *int64   { return &i }

// --- OTLP JSON wire types (minimal subset for traces) ---

type otlpTraceRequest struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Events            []otlpEvent    `json:"events,omitempty"`
}

type otlpEvent struct {
	Name         string         `json:"name"`
	TimeUnixNano string         `json:"timeUnixNano"`
	Attributes   []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *int64  `json:"intValue,omitempty"`
}
