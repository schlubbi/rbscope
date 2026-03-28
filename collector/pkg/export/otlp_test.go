package export

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

func TestOTLPExporter_AccumulateSamples(t *testing.T) {
	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    "http://localhost:1/v1/traces",
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	ctx := context.Background()
	if err := e.Export(ctx, makeSampleEvent("Object#foo")); err != nil {
		t.Fatalf("Export sample: %v", err)
	}
	if err := e.Export(ctx, makeSampleEvent("Bar#baz")); err != nil {
		t.Fatalf("Export sample: %v", err)
	}

	e.mu.Lock()
	count := len(e.samples)
	e.mu.Unlock()

	if count != 2 {
		t.Errorf("expected 2 accumulated samples, got %d", count)
	}
}

func TestOTLPExporter_AccumulateSpans(t *testing.T) {
	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    "http://localhost:1/v1/traces",
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	span := &collector.RubySpanEvent{
		EventHeader: collector.EventHeader{
			Type:      3, // EventRubySpan
			PID:       1234,
			TID:       5678,
			Timestamp: uint64(time.Now().UnixNano()),
		},
		TraceID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:   [8]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		ParentID: [8]byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8},
		Enter:    0,
	}

	ctx := context.Background()
	if err := e.Export(ctx, span); err != nil {
		t.Fatalf("Export span: %v", err)
	}

	e.mu.Lock()
	count := len(e.spans)
	e.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 accumulated span, got %d", count)
	}
}

func TestOTLPExporter_SkipsUnknownEvents(t *testing.T) {
	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    "http://localhost:1",
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	ioEvent := &collector.IOEvent{
		EventHeader: collector.EventHeader{Type: collector.EventIO},
	}
	if err := e.Export(context.Background(), ioEvent); err != nil {
		t.Fatalf("Export: %v", err)
	}

	e.mu.Lock()
	samples := len(e.samples)
	spans := len(e.spans)
	e.mu.Unlock()

	if samples != 0 || spans != 0 {
		t.Errorf("expected 0 samples/spans for IO event, got %d/%d", samples, spans)
	}
}

func TestOTLPExporter_FlushEmptyNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request for empty flush")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:   srv.URL,
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	if err := e.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func TestOTLPExporter_FlushSamples(t *testing.T) {
	var gotPayload otlpTraceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    srv.URL,
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	ctx := context.Background()
	_ = e.Export(ctx, makeSampleEvent("UsersController#index"))
	_ = e.Export(ctx, makeSampleEvent("PostsController#show"))

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Verify OTLP structure
	if len(gotPayload.ResourceSpans) != 1 {
		t.Fatalf("expected 1 resourceSpan, got %d", len(gotPayload.ResourceSpans))
	}

	rs := gotPayload.ResourceSpans[0]

	// Check service.name
	foundService := false
	for _, attr := range rs.Resource.Attributes {
		if attr.Key == "service.name" && attr.Value.StringValue != nil && *attr.Value.StringValue == "test-app" {
			foundService = true
		}
	}
	if !foundService {
		t.Error("expected service.name=test-app in resource attributes")
	}

	// Check scope
	if len(rs.ScopeSpans) != 1 {
		t.Fatalf("expected 1 scopeSpan, got %d", len(rs.ScopeSpans))
	}
	if rs.ScopeSpans[0].Scope.Name != "rbscope-collector" {
		t.Errorf("expected scope name 'rbscope-collector', got %q", rs.ScopeSpans[0].Scope.Name)
	}

	// Both samples have PID 1234, so they should be grouped into 1 summary span
	spans := rs.ScopeSpans[0].Spans
	if len(spans) != 1 {
		t.Fatalf("expected 1 span (samples grouped by PID), got %d", len(spans))
	}

	span := spans[0]
	if span.Name != "rbscope.cpu.profile [pid:1234]" {
		t.Errorf("expected span name containing pid:1234, got %q", span.Name)
	}

	// Check attributes
	attrMap := make(map[string]any)
	for _, attr := range span.Attributes {
		if attr.Value.IntValue != nil {
			attrMap[attr.Key] = *attr.Value.IntValue
		} else if attr.Value.StringValue != nil {
			attrMap[attr.Key] = *attr.Value.StringValue
		}
	}
	if attrMap["sample_count"] != int64(2) {
		t.Errorf("expected sample_count=2, got %v", attrMap["sample_count"])
	}
	if attrMap["profiler"] != "rbscope" {
		t.Errorf("expected profiler=rbscope, got %v", attrMap["profiler"])
	}

	// Check span events (one per sample)
	if len(span.Events) != 2 {
		t.Errorf("expected 2 span events, got %d", len(span.Events))
	}
	for _, ev := range span.Events {
		if ev.Name != "stack_sample" {
			t.Errorf("expected event name 'stack_sample', got %q", ev.Name)
		}
	}
}

func TestOTLPExporter_FlushSpans(t *testing.T) {
	var gotPayload otlpTraceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    srv.URL,
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	span := &collector.RubySpanEvent{
		EventHeader: collector.EventHeader{
			Type:      3,
			PID:       1234,
			TID:       5678,
			Timestamp: uint64(time.Now().UnixNano()),
		},
		TraceID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:   [8]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		ParentID: [8]byte{},
		Enter:    0,
	}

	ctx := context.Background()
	_ = e.Export(ctx, span)

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	spans := gotPayload.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	s := spans[0]
	if s.Name != "ruby.span" {
		t.Errorf("expected name 'ruby.span', got %q", s.Name)
	}

	// Verify trace ID encoding
	expectedTraceID := "0102030405060708090a0b0c0d0e0f10"
	if s.TraceID != expectedTraceID {
		t.Errorf("traceID: got %q, want %q", s.TraceID, expectedTraceID)
	}
	expectedSpanID := "a1a2a3a4a5a6a7a8"
	if s.SpanID != expectedSpanID {
		t.Errorf("spanID: got %q, want %q", s.SpanID, expectedSpanID)
	}
}

func TestOTLPExporter_FlushHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:   srv.URL,
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	_ = e.Export(context.Background(), makeSampleEvent("main"))

	err := e.Flush(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestOTLPExporter_CloseFlushesRemaining(t *testing.T) {
	pushed := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:   srv.URL,
		FlushEvery: 10 * time.Minute,
	})

	_ = e.Export(context.Background(), makeSampleEvent("main"))

	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !pushed {
		t.Error("expected Close() to flush remaining data")
	}
}

func TestOTLPExporter_EndpointNormalization(t *testing.T) {
	tests := []struct {
		input    string
		wantPath string
	}{
		{"http://localhost:4318", "/v1/traces"},
		{"http://localhost:4318/", "/v1/traces"},
		{"http://localhost:4318/v1/traces", "/v1/traces"},
	}

	for _, tt := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != tt.wantPath {
				t.Errorf("input %q: got path %q, want %q", tt.input, r.URL.Path, tt.wantPath)
			}
			w.WriteHeader(http.StatusOK)
		}))

		e := NewOTLPExporter(OTLPConfig{
			Endpoint:   srv.URL + tt.input[len("http://localhost:4318"):],
			FlushEvery: 10 * time.Minute,
		})

		_ = e.Export(context.Background(), makeSampleEvent("main"))
		_ = e.Flush(context.Background())

		e.cancel()
		srv.Close()
	}
}

func TestOTLPExporter_MixedSamplesAndSpans(t *testing.T) {
	var gotPayload otlpTraceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewOTLPExporter(OTLPConfig{
		Endpoint:    srv.URL,
		ServiceName: "test-app",
		FlushEvery:  10 * time.Minute,
	})
	defer e.cancel()

	ctx := context.Background()

	// Add a sample
	_ = e.Export(ctx, makeSampleEvent("main"))

	// Add a span
	span := &collector.RubySpanEvent{
		EventHeader: collector.EventHeader{
			Type:      3,
			PID:       9999,
			TID:       1111,
			Timestamp: uint64(time.Now().UnixNano()),
		},
		TraceID: [16]byte{0xff},
		SpanID:  [8]byte{0xee},
		Enter:   1,
	}
	_ = e.Export(ctx, span)

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Should have 2 spans: 1 ruby.span.enter + 1 profiling summary
	spans := gotPayload.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans (1 real + 1 summary), got %d", len(spans))
	}

	names := map[string]bool{}
	for _, s := range spans {
		names[s.Name] = true
	}
	if !names["ruby.span.enter"] {
		t.Error("expected ruby.span.enter span")
	}
	if !names["rbscope.cpu.profile [pid:1234]"] {
		t.Errorf("expected profiling summary span, got names: %v", names)
	}
}
