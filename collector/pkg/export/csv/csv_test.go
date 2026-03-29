package csv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func testCapture() *pb.Capture {
	return &pb.Capture{
		Header: &pb.CaptureHeader{
			Pid:               1234,
			SampleFrequencyHz: 99,
		},
		StringTable: []string{
			"",                           // 0
			"PostsController#index",      // 1
			"posts_controller.rb",        // 2
			"read",                       // 3
			"tcp:10.0.0.1:54321→db:3306", // 4
		},
		FrameTable: []*pb.StackFrame{
			{FunctionNameIdx: 1, FileNameIdx: 2, LineNumber: 15},
		},
		Threads: []*pb.ThreadTimeline{
			{
				ThreadId: 100,
				Samples: []*pb.Sample{
					{TimestampNs: 1000, FrameIds: []uint32{0}, Weight: 1},
					{TimestampNs: 2000, FrameIds: []uint32{0}, Weight: 3},
				},
				IoEvents: []*pb.IOEvent{
					{
						TimestampNs: 1500, SyscallIdx: 3, Fd: 7,
						Bytes: 4096, LatencyNs: 2_000_000,
						FdInfoIdx: 4, FdType: pb.FdType_FD_TCP,
						LocalPort: 54321, RemotePort: 3306,
					},
				},
				SchedEvents: []*pb.SchedEvent{
					{
						TimestampNs: 1500, OffCpuNs: 1_800_000,
						Reason: pb.OffCPUReason_OFF_CPU_IO_BLOCKED,
					},
				},
			},
		},
	}
}

func TestExport_CreateFiles(t *testing.T) {
	dir := t.TempDir()
	capture := testCapture()

	if err := Export(capture, dir); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for _, name := range []string{"rbscope_samples.csv", "rbscope_io.csv", "rbscope_sched.csv"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing file: %s", name)
		}
	}
}

func TestExport_SamplesContent(t *testing.T) {
	dir := t.TempDir()
	capture := testCapture()
	_ = Export(capture, dir)

	data, _ := os.ReadFile(filepath.Join(dir, "rbscope_samples.csv"))
	content := string(data)

	// Check header
	if !strings.Contains(content, "timestamp_ns,pid,tid,weight") {
		t.Error("missing samples header")
	}
	// Check data
	if !strings.Contains(content, "PostsController#index") {
		t.Error("missing leaf method")
	}
	if !strings.Contains(content, "posts_controller.rb") {
		t.Error("missing leaf file")
	}
	// Check we have 2 data rows (+ 1 header)
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (header + 2 samples), got %d", len(lines))
	}
}

func TestExport_IOContent(t *testing.T) {
	dir := t.TempDir()
	capture := testCapture()
	_ = Export(capture, dir)

	data, _ := os.ReadFile(filepath.Join(dir, "rbscope_io.csv"))
	content := string(data)

	if !strings.Contains(content, "read") {
		t.Error("missing syscall")
	}
	if !strings.Contains(content, "tcp:10.0.0.1:54321") {
		t.Error("missing connection info")
	}
	if !strings.Contains(content, "2000000") {
		t.Error("missing latency")
	}
}

func TestExport_SchedContent(t *testing.T) {
	dir := t.TempDir()
	capture := testCapture()
	_ = Export(capture, dir)

	data, _ := os.ReadFile(filepath.Join(dir, "rbscope_sched.csv"))
	content := string(data)

	if !strings.Contains(content, "1800000") {
		t.Error("missing off_cpu duration")
	}
	if !strings.Contains(content, "OFF_CPU_IO_BLOCKED") {
		t.Error("missing reason")
	}
}

func TestExport_EmptyCapture(t *testing.T) {
	dir := t.TempDir()
	capture := &pb.Capture{
		Header:      &pb.CaptureHeader{Pid: 1},
		StringTable: []string{""},
	}

	if err := Export(capture, dir); err != nil {
		t.Fatalf("Export empty: %v", err)
	}

	// Files should exist with headers only
	data, _ := os.ReadFile(filepath.Join(dir, "rbscope_samples.csv"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line (header only), got %d", len(lines))
	}
}

func TestFormatStack(t *testing.T) {
	capture := testCapture()
	// Add a second frame
	capture.StringTable = append(capture.StringTable, "ApplicationController#set_locale")
	capture.FrameTable = append(capture.FrameTable, &pb.StackFrame{
		FunctionNameIdx: 5, FileNameIdx: 2, LineNumber: 8,
	})

	// Stack with 2 frames (leaf-first: index, set_locale)
	stack := formatStack(capture, []uint32{0, 1})
	// Root first: set_locale;PostsController#index
	if stack != "ApplicationController#set_locale;PostsController#index" {
		t.Errorf("stack: got %q", stack)
	}
}
