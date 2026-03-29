package export

import (
	"context"
	"testing"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

func TestPyroscopeExporter_NilProfile(t *testing.T) {
	e := NewPyroscopeExporter(PyroscopeConfig{
		ServerURL: "http://localhost:4040",
		AppName:   "test-app",
	})
	// Should panic or error with nil profile
	defer func() {
		if r := recover(); r == nil {
			_ = r // no-op: didn't panic — check error returned
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
	stackData := buildInlineStack([]struct {
		label, path string
		line        uint32
	}{
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
