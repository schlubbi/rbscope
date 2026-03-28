package export

import (
	"context"
	"testing"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

func TestPprofBuilder_Empty(t *testing.T) {
	b := NewPprofBuilder(int64(52631578)) // 19Hz
	p := b.Build()

	if p == nil {
		t.Fatal("Build() returned nil")
	}
	if len(p.Sample) != 0 {
		t.Errorf("expected 0 samples, got %d", len(p.Sample))
	}
}

func TestPprofBuilder_AddSample(t *testing.T) {
	b := NewPprofBuilder(int64(10101010))

	labels := map[string]string{"trace_id": "abc123"}
	b.AddSample(1, labels, 1)
	b.AddSample(1, labels, 1)
	b.AddSample(2, nil, 1)

	p := b.Build()

	if len(p.Sample) != 3 {
		t.Errorf("expected 3 samples, got %d", len(p.Sample))
	}

	// Verify we have locations (two unique stackIDs: 1 and 2)
	if len(p.Location) != 2 {
		t.Errorf("expected 2 locations, got %d", len(p.Location))
	}
}

func TestPprofBuilder_Flush(t *testing.T) {
	b := NewPprofBuilder(int64(52631578))

	b.AddSample(1, nil, 1)
	p1 := b.Flush()
	if len(p1.Sample) != 1 {
		t.Errorf("first flush: expected 1 sample, got %d", len(p1.Sample))
	}

	// After flush, builder should be empty
	p2 := b.Build()
	if len(p2.Sample) != 0 {
		t.Errorf("after flush: expected 0 samples, got %d", len(p2.Sample))
	}
}

func TestPyroscopeExporter_NilProfile(t *testing.T) {
	e := NewPyroscopeExporter(PyroscopeConfig{
		ServerURL: "http://localhost:4040",
		AppName:   "test-app",
	})
	// Should panic or error with nil profile
	defer func() {
		if r := recover(); r == nil {
			// no-op: didn't panic — check error returned
		}
	}()
	err := e.Push(context.TODO(), nil)
	if err == nil {
		t.Log("Push with nil profile returned nil error (may panic instead)")
	}
}

func TestFileExporter_CreateClose(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.rbscope"

	e, err := NewFileExporter(path)
	if err != nil {
		t.Fatalf("NewFileExporter: %v", err)
	}
	defer e.Close()

	// Write a dummy event
	err = e.WriteRaw("rbscope.test", []byte("test data"))
	if err != nil {
		t.Errorf("WriteRaw: %v", err)
	}
}

func TestPyroscopePushExporter_InlineStack(t *testing.T) {
	// Build a format v2 inline stack with 2 frames
	stackData := buildInlineStack([]struct{ label, path string; line uint32 }{
		{"UsersController#index", "/app/controllers/users_controller.rb", 15},
		{"ActionController::Base#process", "/gems/actionpack/base.rb", 42},
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

	cfg := PyroscopePushConfig{
		ServerURL:  "http://localhost:4040",
		AppName:    "test-app",
		FlushEvery: 10 * time.Minute,
	}
	e := NewPyroscopePushExporter(cfg)
	defer e.cancel()

	ctx := context.Background()
	if err := e.Export(ctx, sample); err != nil {
		t.Fatalf("Export: %v", err)
	}

	e.mu.Lock()
	sampleCount := len(e.builder.Sample)
	funcCount := len(e.builder.Function)
	e.mu.Unlock()

	if sampleCount != 1 {
		t.Errorf("expected 1 sample, got %d", sampleCount)
	}
	if funcCount != 2 {
		t.Errorf("expected 2 functions (one per frame), got %d", funcCount)
	}
}
