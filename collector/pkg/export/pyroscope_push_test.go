package export

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

func TestPyroscopePushExporter_FlushPushesValidPprof(t *testing.T) {
	var (
		gotPath        string
		gotContentType string
		gotPprof       *profile.Profile
		gotQuery       map[string]string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotQuery = map[string]string{
			"name":   r.URL.Query().Get("name"),
			"format": r.URL.Query().Get("format"),
		}

		body, _ := io.ReadAll(r.Body)
		p, err := profile.ParseData(body)
		if err != nil {
			t.Fatalf("parse pprof from push: %v", err)
		}
		gotPprof = p
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewPyroscopePushExporter(PyroscopePushConfig{
		ServerURL:  srv.URL,
		AppName:    "rbscope.cpu",
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	ctx := context.Background()

	// Add 3 samples with 2 different stacks
	_ = e.Export(ctx, makeSampleEvent("UsersController#index"))
	_ = e.Export(ctx, makeSampleEvent("UsersController#index"))
	_ = e.Export(ctx, makeSampleEvent("PostsController#show"))

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if gotPath != "/ingest" {
		t.Errorf("expected path /ingest, got %q", gotPath)
	}
	if gotContentType != "application/octet-stream" {
		t.Errorf("expected content-type application/octet-stream, got %q", gotContentType)
	}
	if gotQuery["format"] != "pprof" {
		t.Errorf("expected format=pprof, got %q", gotQuery["format"])
	}
	if gotQuery["name"] != "rbscope.cpu" {
		t.Errorf("expected name=rbscope.cpu, got %q", gotQuery["name"])
	}

	if gotPprof == nil {
		t.Fatal("no pprof received")
	}
	if len(gotPprof.Sample) != 3 {
		t.Errorf("expected 3 samples, got %d", len(gotPprof.Sample))
	}

	// Verify functions exist
	funcNames := map[string]bool{}
	for _, fn := range gotPprof.Function {
		funcNames[fn.Name] = true
	}
	if !funcNames["UsersController#index"] {
		t.Error("missing function UsersController#index")
	}
	if !funcNames["PostsController#show"] {
		t.Error("missing function PostsController#show")
	}
}

func TestPyroscopePushExporter_FlushClearsAccumulator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewPyroscopePushExporter(PyroscopePushConfig{
		ServerURL:  srv.URL,
		AppName:    "test",
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	ctx := context.Background()
	_ = e.Export(ctx, makeSampleEvent("main"))

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("first flush: %v", err)
	}

	// Second flush should be a no-op (no HTTP call)
	callCount := 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	e.pyro.serverURL = srv2.URL

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if callCount != 0 {
		t.Error("expected no HTTP call for empty flush")
	}
}

func TestPyroscopePushExporter_HTTPErrorReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("overloaded"))
	}))
	defer srv.Close()

	e := NewPyroscopePushExporter(PyroscopePushConfig{
		ServerURL:  srv.URL,
		AppName:    "test",
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	_ = e.Export(context.Background(), makeSampleEvent("main"))
	err := e.Flush(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
}

func TestPyroscopePushExporter_SkipsEmptyStacks(t *testing.T) {
	e := NewPyroscopePushExporter(PyroscopePushConfig{
		ServerURL:  "http://localhost:1",
		AppName:    "test",
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	// Sample with empty stack data — should be skipped
	sample := &collector.RubySampleEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventRubySample,
			PID:  1234,
		},
		StackData:    nil,
		StackDataLen: 0,
	}

	if err := e.Export(context.Background(), sample); err != nil {
		t.Fatalf("Export: %v", err)
	}

	e.mu.Lock()
	count := len(e.builder.Sample)
	e.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 samples for empty stack, got %d", count)
	}
}

func TestPyroscopePushExporter_MultiFrameStack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewPyroscopePushExporter(PyroscopePushConfig{
		ServerURL:  srv.URL,
		AppName:    "test",
		FlushEvery: 10 * time.Minute,
	})
	defer e.cancel()

	// Build a 4-frame stack
	stackData := buildInlineStack([]struct{ label, path string; line uint32 }{
		{"ActiveRecord::Base.find", "/gems/ar/base.rb", 100},
		{"PostsController#show", "/app/controllers/posts_controller.rb", 25},
		{"ActionController::Metal#dispatch", "/gems/actionpack/metal.rb", 80},
		{"Rack::Runtime#call", "/gems/rack/runtime.rb", 15},
	})

	sample := &collector.RubySampleEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventRubySample,
			PID:       1234,
			TID:       5678,
			Timestamp: uint64(time.Now().UnixNano()),
		},
		ThreadID:     99,
		StackDataLen: uint32(len(stackData)),
		StackData:    stackData,
	}

	ctx := context.Background()
	_ = e.Export(ctx, sample)

	e.mu.Lock()
	sampleCount := len(e.builder.Sample)
	locCount := len(e.builder.Location)
	funcCount := len(e.builder.Function)
	e.mu.Unlock()

	if sampleCount != 1 {
		t.Errorf("expected 1 sample, got %d", sampleCount)
	}
	if locCount != 4 {
		t.Errorf("expected 4 locations, got %d", locCount)
	}
	if funcCount != 4 {
		t.Errorf("expected 4 functions, got %d", funcCount)
	}
}
