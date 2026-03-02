package export

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

func makeSampleEvent(stackID uint32) *collector.RubySampleEvent {
	return &collector.RubySampleEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventRubySample,
			PID:       1234,
			TID:       5678,
			Timestamp: uint64(time.Now().UnixNano()),
		},
		StackID:  stackID,
		StackLen: 1,
	}
}

func newTestExporter(url string) *DatadogExporter {
	cfg := DatadogConfig{
		IntakeURL:  url,
		APIKey:     "test-api-key",
		Service:    "test-service",
		Env:        "test",
		Version:    "1.0.0",
		Tags:       map[string]string{"host": "test-host"},
		SymbolMap: map[uint32][]string{
			1: {"main", "ActiveRecord::Base#find"},
			2: {"main", "ActionController::Base#process"},
		},
		FlushEvery: 10 * time.Minute, // large value so the background loop doesn't fire
	}
	return NewDatadogExporter(cfg)
}

func TestDatadogExporter_AccumulateSamples(t *testing.T) {
	e := newTestExporter("http://localhost:1")
	defer e.cancel() // stop flush loop without pushing

	ctx := context.Background()
	if err := e.Export(ctx, makeSampleEvent(1)); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := e.Export(ctx, makeSampleEvent(2)); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := e.Export(ctx, makeSampleEvent(1)); err != nil {
		t.Fatalf("Export: %v", err)
	}

	e.mu.Lock()
	sampleCount := len(e.builder.Sample)
	e.mu.Unlock()

	if sampleCount != 3 {
		t.Errorf("expected 3 accumulated samples, got %d", sampleCount)
	}
}

func TestDatadogExporter_SkipsNonSampleEvents(t *testing.T) {
	e := newTestExporter("http://localhost:1")
	defer e.cancel()

	ctx := context.Background()
	ioEvent := &collector.IOEvent{
		EventHeader: collector.EventHeader{Type: collector.EventIO},
	}
	if err := e.Export(ctx, ioEvent); err != nil {
		t.Fatalf("Export: %v", err)
	}

	e.mu.Lock()
	sampleCount := len(e.builder.Sample)
	e.mu.Unlock()

	if sampleCount != 0 {
		t.Errorf("expected 0 samples for non-sample event, got %d", sampleCount)
	}
}

func TestDatadogExporter_MultipartForm(t *testing.T) {
	var (
		gotAPIKey     string
		gotEvent      datadogEvent
		gotPprofBytes []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/v2/profile") {
			t.Errorf("expected path ending /api/v2/profile, got %s", r.URL.Path)
		}

		gotAPIKey = r.Header.Get("DD-API-KEY")

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse content type: %v", err)
		}
		if !strings.HasPrefix(mediaType, "multipart/") {
			t.Fatalf("expected multipart content type, got %s", mediaType)
		}

		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("read part: %v", err)
			}

			data, _ := io.ReadAll(part)
			switch part.FormName() {
			case "event":
				if err := json.Unmarshal(data, &gotEvent); err != nil {
					t.Fatalf("unmarshal event: %v", err)
				}
			case "profile.pprof":
				gotPprofBytes = data
			}
			part.Close()
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestExporter(srv.URL)
	defer e.cancel()

	ctx := context.Background()
	_ = e.Export(ctx, makeSampleEvent(1))
	_ = e.Export(ctx, makeSampleEvent(2))

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Verify API key header
	if gotAPIKey != "test-api-key" {
		t.Errorf("expected API key 'test-api-key', got %q", gotAPIKey)
	}

	// Verify event metadata
	if gotEvent.Family != "ruby" {
		t.Errorf("expected family 'ruby', got %q", gotEvent.Family)
	}
	if gotEvent.Version != "4" {
		t.Errorf("expected version '4', got %q", gotEvent.Version)
	}
	if len(gotEvent.Attachments) != 1 || gotEvent.Attachments[0] != "profile.pprof" {
		t.Errorf("unexpected attachments: %v", gotEvent.Attachments)
	}
	if !strings.Contains(gotEvent.TagsProfiler, "service:test-service") {
		t.Errorf("tags_profiler missing service: %q", gotEvent.TagsProfiler)
	}
	if !strings.Contains(gotEvent.TagsProfiler, "language:ruby") {
		t.Errorf("tags_profiler missing language: %q", gotEvent.TagsProfiler)
	}

	// Verify pprof is parseable
	if len(gotPprofBytes) == 0 {
		t.Fatal("profile.pprof part was empty")
	}
	prof, err := profile.ParseData(gotPprofBytes)
	if err != nil {
		t.Fatalf("parse pprof: %v", err)
	}
	if len(prof.Sample) != 2 {
		t.Errorf("expected 2 samples in pprof, got %d", len(prof.Sample))
	}
}

func TestDatadogExporter_CloseFlushesRemaining(t *testing.T) {
	pushed := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestExporter(srv.URL)

	ctx := context.Background()
	_ = e.Export(ctx, makeSampleEvent(1))

	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !pushed {
		t.Error("expected Close() to flush remaining samples, but no push was received")
	}
}

func TestDatadogExporter_FlushEmptyNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request for empty flush")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestExporter(srv.URL)
	defer e.cancel()

	if err := e.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
