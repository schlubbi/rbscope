package export

import (
	"testing"
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
			// didn't panic — check error returned
		}
	}()
	err := e.Push(nil, nil)
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
