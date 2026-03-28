package gecko

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// testCapture builds a minimal Capture for testing.
func testCapture() *pb.Capture {
	return &pb.Capture{
		Header: &pb.CaptureHeader{
			Version:           2,
			ServiceName:       "test-app",
			Hostname:          "test-host",
			Pid:               1234,
			StartTimeNs:       1_000_000_000_000, // 1000s epoch in ns
			EndTimeNs:         1_030_000_000_000, // +30s
			SampleFrequencyHz: 99,
		},
		StringTable: []string{
			"",                                    // 0: empty
			"main",                                // 1: thread name
			"PostsController#index",               // 2: function
			"app/controllers/posts_controller.rb", // 3: file
			"ApplicationController#set_locale",    // 4: function
			"app/controllers/application_controller.rb", // 5: file
			"read",                             // 6: syscall
			"tcp:10.0.0.1:54321→10.0.0.2:3306", // 7: fd info
			"worker",                           // 8: thread name
		},
		FrameTable: []*pb.StackFrame{
			{FunctionNameIdx: 2, FileNameIdx: 3, LineNumber: 15}, // 0: PostsController#index
			{FunctionNameIdx: 4, FileNameIdx: 5, LineNumber: 8},  // 1: ApplicationController#set_locale
		},
		Threads: []*pb.ThreadTimeline{
			{
				ThreadId:      100,
				ThreadNameIdx: 1, // "main"
				Samples: []*pb.Sample{
					{
						TimestampNs: 1_000_010_000_000, // +10ms
						FrameIds:    []uint32{0, 1},    // leaf=PostsController, root=ApplicationController
						Weight:      1,
					},
					{
						TimestampNs: 1_000_020_000_000, // +20ms
						FrameIds:    []uint32{0, 1},    // same stack
						Weight:      3,                 // cached weight
					},
				},
				IoEvents: []*pb.IOEvent{
					{
						TimestampNs: 1_000_015_000_000, // +15ms
						SyscallIdx:  6,                 // "read"
						Fd:          7,
						Bytes:       4096,
						LatencyNs:   2_000_000, // 2ms
						FdInfoIdx:   7,         // "tcp:10.0.0.1:54321→10.0.0.2:3306"
						FdType:      pb.FdType_FD_TCP,
						LocalPort:   54321,
						RemotePort:  3306,
					},
				},
				SchedEvents: []*pb.SchedEvent{
					{
						TimestampNs: 1_000_015_000_000,
						OffCpuNs:    1_500_000, // 1.5ms
						Reason:      pb.OffCPUReason_OFF_CPU_IO_BLOCKED,
					},
				},
				States: []*pb.ThreadStateInterval{
					{
						StartNs: 1_000_000_000_000,
						EndNs:   1_000_013_500_000,
						State:   pb.ThreadState_THREAD_STATE_RUNNING,
					},
					{
						StartNs: 1_000_013_500_000,
						EndNs:   1_000_015_000_000,
						State:   pb.ThreadState_THREAD_STATE_OFF_CPU_IO,
					},
					{
						StartNs: 1_000_015_000_000,
						EndNs:   1_000_030_000_000,
						State:   pb.ThreadState_THREAD_STATE_IDLE,
					},
				},
			},
		},
	}
}

func TestBuild_TopLevel(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	if profile.Meta.Version != 33 {
		t.Errorf("version: got %d, want 33", profile.Meta.Version)
	}
	if profile.Meta.Product != "rbscope — test-app" {
		t.Errorf("product: got %q", profile.Meta.Product)
	}
	if len(profile.Meta.Categories) != 8 {
		t.Errorf("categories: got %d, want 8", len(profile.Meta.Categories))
	}
	if len(profile.Meta.MarkerSchema) != 4 {
		t.Errorf("marker schemas: got %d, want 4", len(profile.Meta.MarkerSchema))
	}
}

func TestBuild_Thread(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	if len(profile.Threads) != 1 {
		t.Fatalf("threads: got %d, want 1", len(profile.Threads))
	}

	thread := profile.Threads[0]
	if thread.Name != "main" {
		t.Errorf("thread name: got %q, want %q", thread.Name, "main")
	}
	if thread.PID != 1234 {
		t.Errorf("pid: got %d, want %d", thread.PID, 1234)
	}
	if thread.TID != 100 {
		t.Errorf("tid: got %d, want %d", thread.TID, 100)
	}
}

func TestBuild_Samples(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	samples := profile.Threads[0].Samples
	if len(samples.Data) != 2 {
		t.Fatalf("samples.data length: got %d, want 2", len(samples.Data))
	}

	// First sample should have a stack reference (not nil)
	if samples.Data[0][0] == nil {
		t.Error("first sample stack is nil")
	}

	// Time should be relative to start (10ms)
	timeMs, ok := samples.Data[0][1].(float64)
	if !ok || timeMs != 10.0 {
		t.Errorf("first sample time: got %v, want 10.0", samples.Data[0][1])
	}
}

func TestBuild_PerThreadTables(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	thread := profile.Threads[0]

	// Should have per-thread string table
	if len(thread.StringTable) == 0 {
		t.Error("string table is empty")
	}

	// Should have frame table entries
	if len(thread.FrameTable.Data) < 2 {
		t.Errorf("frame table: got %d entries, want >= 2", len(thread.FrameTable.Data))
	}

	// Should have stack table entries (prefix tree)
	if len(thread.StackTable.Data) < 2 {
		t.Errorf("stack table: got %d entries, want >= 2", len(thread.StackTable.Data))
	}

	// First stack entry should have nil prefix (root)
	if thread.StackTable.Data[0][0] != nil {
		t.Errorf("stack[0] prefix: got %v, want nil", thread.StackTable.Data[0][0])
	}
}

func TestBuild_IOMarkers(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	markers := profile.Threads[0].Markers
	if len(markers.Data) == 0 {
		t.Fatal("no markers")
	}

	// Find the IO marker
	found := false
	for _, tuple := range markers.Data {
		if len(tuple) < 6 {
			continue
		}
		data, ok := tuple[5].(map[string]any)
		if !ok {
			continue
		}
		if data["type"] == "rbscope-io" {
			found = true
			if data["syscall"] != "read" {
				t.Errorf("io marker syscall: got %v, want %q", data["syscall"], "read")
			}
			if data["fdInfo"] != "tcp:10.0.0.1:54321→10.0.0.2:3306" {
				t.Errorf("io marker fdInfo: got %v", data["fdInfo"])
			}
			// Phase should be Interval (1)
			if tuple[3] != MarkerPhaseInterval {
				t.Errorf("io marker phase: got %v, want %d", tuple[3], MarkerPhaseInterval)
			}
			break
		}
	}
	if !found {
		t.Error("no rbscope-io marker found")
	}
}

func TestBuild_ThreadStateMarkers(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	markers := profile.Threads[0].Markers
	stateTypes := make(map[string]bool)
	for _, tuple := range markers.Data {
		if len(tuple) < 6 {
			continue
		}
		data, ok := tuple[5].(map[string]any)
		if !ok {
			continue
		}
		if data["type"] == "rbscope-state" {
			stateTypes[data["state"].(string)] = true
		}
	}

	expected := []string{"THREAD_STATE_RUNNING", "THREAD_STATE_OFF_CPU_IO", "THREAD_STATE_IDLE"}
	for _, s := range expected {
		if !stateTypes[s] {
			t.Errorf("missing state marker: %s", s)
		}
	}
}

func TestBuild_Categories(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	cats := profile.Meta.Categories
	expected := []string{"Other", "Ruby", "I/O", "GVL", "GC", "Kernel", "OTel", "Idle"}
	for i, want := range expected {
		if i >= len(cats) || cats[i].Name != want {
			t.Errorf("category[%d]: got %q, want %q", i, cats[i].Name, want)
		}
	}
}

func TestBuild_EmptyCapture(t *testing.T) {
	capture := &pb.Capture{
		Header: &pb.CaptureHeader{
			Version:           2,
			ServiceName:       "empty",
			SampleFrequencyHz: 99,
		},
		StringTable: []string{""},
	}

	profile := Build(capture)
	if len(profile.Threads) != 0 {
		t.Errorf("expected 0 threads, got %d", len(profile.Threads))
	}
}

func TestBuild_EmptyThread(t *testing.T) {
	capture := &pb.Capture{
		Header: &pb.CaptureHeader{
			Version:           2,
			ServiceName:       "test",
			SampleFrequencyHz: 99,
		},
		StringTable: []string{"", "idle-thread"},
		Threads: []*pb.ThreadTimeline{
			{ThreadId: 42, ThreadNameIdx: 1},
		},
	}

	profile := Build(capture)
	if len(profile.Threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(profile.Threads))
	}
	if len(profile.Threads[0].Samples.Data) != 0 {
		t.Errorf("expected 0 samples, got %d", len(profile.Threads[0].Samples.Data))
	}
	if len(profile.Threads[0].Markers.Data) != 0 {
		t.Errorf("expected 0 markers, got %d", len(profile.Threads[0].Markers.Data))
	}
}

func TestExport_WritesValidJSON(t *testing.T) {
	capture := testCapture()
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")

	if err := Export(capture, path); err != nil {
		t.Fatalf("Export: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, key := range []string{"meta", "libs", "threads", "processes", "pausedRanges"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing top-level key: %s", key)
		}
	}
}

func TestExport_Gzip(t *testing.T) {
	capture := testCapture()
	dir := t.TempDir()
	gzPath := filepath.Join(dir, "profile.json.gz")
	plainPath := filepath.Join(dir, "profile.json")

	if err := Export(capture, gzPath); err != nil {
		t.Fatalf("Export gzip: %v", err)
	}
	if err := Export(capture, plainPath); err != nil {
		t.Fatalf("Export plain: %v", err)
	}

	gzData, _ := os.ReadFile(gzPath)
	plainData, _ := os.ReadFile(plainPath)

	if len(gzData) >= len(plainData) {
		t.Errorf("gzip (%d bytes) should be smaller than plain (%d bytes)", len(gzData), len(plainData))
	}

	if len(gzData) < 2 || gzData[0] != 0x1f || gzData[1] != 0x8b {
		t.Error("gzip output missing magic bytes")
	}

	f, _ := os.Open(gzPath)
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	decoded, _ := io.ReadAll(gr)
	var parsed map[string]any
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("decompressed JSON invalid: %v", err)
	}
}

func TestBuild_MultipleThreads(t *testing.T) {
	capture := testCapture()
	capture.Threads = append(capture.Threads, &pb.ThreadTimeline{
		ThreadId:      200,
		ThreadNameIdx: 8, // "worker"
		Samples: []*pb.Sample{
			{TimestampNs: 1_000_010_000_000, FrameIds: []uint32{0}, Weight: 1},
		},
	})

	profile := Build(capture)
	if len(profile.Threads) != 2 {
		t.Fatalf("threads: got %d, want 2", len(profile.Threads))
	}
	if profile.Threads[0].Name != "main" {
		t.Errorf("thread[0] name: got %q", profile.Threads[0].Name)
	}
	if profile.Threads[1].Name != "worker" {
		t.Errorf("thread[1] name: got %q", profile.Threads[1].Name)
	}
}

func TestBuild_StackSharing(t *testing.T) {
	capture := testCapture()
	profile := Build(capture)

	samples := profile.Threads[0].Samples
	if len(samples.Data) < 2 {
		t.Fatal("need at least 2 samples")
	}

	// Same stack → same stack table index
	idx0 := samples.Data[0][0]
	idx1 := samples.Data[1][0]
	if idx0 != idx1 {
		t.Errorf("identical stacks got different indices: %v vs %v", idx0, idx1)
	}
}
