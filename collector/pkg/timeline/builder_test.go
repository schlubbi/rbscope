package timeline

import (
	"testing"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
	"google.golang.org/protobuf/proto"
)

// makeStackData builds format v2 inline stack data for testing.
func makeStackData(frames []collector.InlineFrame) []byte {
	var buf []byte
	buf = append(buf, 2) // version
	buf = append(buf, byte(len(frames)), 0)
	for _, f := range frames {
		buf = append(buf, byte(len(f.Label)), byte(len(f.Label)>>8))
		buf = append(buf, []byte(f.Label)...)
		buf = append(buf, byte(len(f.Path)), byte(len(f.Path)>>8))
		buf = append(buf, []byte(f.Path)...)
		buf = append(buf, byte(f.Line), byte(f.Line>>8), byte(f.Line>>16), byte(f.Line>>24))
	}
	return buf
}

func makeSampleEvent(tid uint32, ts uint64, frames []collector.InlineFrame) *collector.RubySampleEvent {
	sd := makeStackData(frames)
	return &collector.RubySampleEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventRubySample,
			TID:       tid,
			Timestamp: ts,
		},
		StackDataLen: uint32(len(sd)),
		StackData:    sd,
	}
}

func makeIOEvent(tid uint32, ts uint64, latNs uint64) *collector.IOEvent {
	return &collector.IOEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventIO,
			TID:       tid,
			Timestamp: ts,
		},
		FD:        5,
		Op:        1, // read
		Bytes:     1024,
		LatencyNs: latNs,
	}
}

func makeSchedEvent(tid uint32, ts uint64, offCPUNs uint64) *collector.SchedEvent {
	return &collector.SchedEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventSched,
			TID:       tid,
			Timestamp: ts,
		},
		OffCPUNs: offCPUNs,
	}
}

func TestBuilderBasicCapture(t *testing.T) {
	b := NewBuilder("test-app", "host1", 1234, 99)

	frames := []collector.InlineFrame{
		{Label: "ApplicationController#show", Path: "app/controllers/application_controller.rb", Line: 42},
		{Label: "ActiveRecord::Base.find", Path: "activerecord/lib/base.rb", Line: 100},
	}

	b.Ingest(makeSampleEvent(100, 1_000_000, frames))
	b.Ingest(makeSampleEvent(100, 2_000_000, frames))
	b.Ingest(makeSampleEvent(200, 1_500_000, frames[:1]))

	capture := b.Build()

	// Header
	if capture.Header.Version != 2 {
		t.Errorf("version = %d, want 2", capture.Header.Version)
	}
	if capture.Header.ServiceName != "test-app" {
		t.Errorf("service = %q, want test-app", capture.Header.ServiceName)
	}
	if capture.Header.Pid != 1234 {
		t.Errorf("pid = %d, want 1234", capture.Header.Pid)
	}

	// Threads
	if len(capture.Threads) != 2 {
		t.Fatalf("threads = %d, want 2", len(capture.Threads))
	}

	// Threads sorted by TID
	if capture.Threads[0].ThreadId != 100 || capture.Threads[1].ThreadId != 200 {
		t.Errorf("thread order: %d, %d", capture.Threads[0].ThreadId, capture.Threads[1].ThreadId)
	}

	// Thread 100 has 2 samples, thread 200 has 1
	if len(capture.Threads[0].Samples) != 2 {
		t.Errorf("thread 100 samples = %d, want 2", len(capture.Threads[0].Samples))
	}
	if len(capture.Threads[1].Samples) != 1 {
		t.Errorf("thread 200 samples = %d, want 1", len(capture.Threads[1].Samples))
	}

	// Samples sorted by timestamp
	if capture.Threads[0].Samples[0].TimestampNs != 1_000_000 {
		t.Errorf("first sample ts = %d", capture.Threads[0].Samples[0].TimestampNs)
	}
}

func TestStringTableDedup(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// Same function name across different samples → deduplicated
	frames := []collector.InlineFrame{
		{Label: "foo", Path: "bar.rb", Line: 1},
	}
	b.Ingest(makeSampleEvent(1, 100, frames))
	b.Ingest(makeSampleEvent(1, 200, frames))

	capture := b.Build()

	// "foo" and "bar.rb" should appear exactly once in string table
	fooCount := 0
	for _, s := range capture.StringTable {
		if s == "foo" {
			fooCount++
		}
	}
	if fooCount != 1 {
		t.Errorf("'foo' appears %d times in string table, want 1", fooCount)
	}

	// Both samples should reference the same frame index
	if len(capture.Threads) != 1 {
		t.Fatal("expected 1 thread")
	}
	s0 := capture.Threads[0].Samples[0].FrameIds
	s1 := capture.Threads[0].Samples[1].FrameIds
	if len(s0) != 1 || len(s1) != 1 || s0[0] != s1[0] {
		t.Errorf("frame dedup failed: s0=%v, s1=%v", s0, s1)
	}
}

func TestFrameTableDedup(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// Two different stacks sharing a common frame
	framesA := []collector.InlineFrame{
		{Label: "a", Path: "a.rb", Line: 1},
		{Label: "shared", Path: "s.rb", Line: 10},
	}
	framesB := []collector.InlineFrame{
		{Label: "b", Path: "b.rb", Line: 2},
		{Label: "shared", Path: "s.rb", Line: 10},
	}
	b.Ingest(makeSampleEvent(1, 100, framesA))
	b.Ingest(makeSampleEvent(1, 200, framesB))

	capture := b.Build()

	// Frame table should have 3 unique frames (a, b, shared)
	if len(capture.FrameTable) != 3 {
		t.Errorf("frame table size = %d, want 3", len(capture.FrameTable))
	}

	// The "shared" frame should be the same index in both samples
	s0 := capture.Threads[0].Samples[0].FrameIds
	s1 := capture.Threads[0].Samples[1].FrameIds
	if s0[1] != s1[1] {
		t.Errorf("shared frame not deduped: s0[1]=%d, s1[1]=%d", s0[1], s1[1])
	}
}

func TestIOToSampleCrossRef(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	b.Ingest(makeSampleEvent(1, 1000, []collector.InlineFrame{{Label: "a", Path: "a.rb", Line: 1}}))
	b.Ingest(makeSampleEvent(1, 3000, []collector.InlineFrame{{Label: "b", Path: "b.rb", Line: 1}}))
	b.Ingest(makeSampleEvent(1, 5000, []collector.InlineFrame{{Label: "c", Path: "c.rb", Line: 1}}))

	// IO at t=2800 → nearest sample should be at t=3000 (index 1)
	b.Ingest(makeIOEvent(1, 2800, 100))

	capture := b.Build()

	io := capture.Threads[0].IoEvents[0]
	if io.NearestSampleIdx != 1 {
		t.Errorf("nearest sample idx = %d, want 1", io.NearestSampleIdx)
	}
}

func TestIOToSchedCrossRef(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// IO from t=1000 with 500ns latency → covers [1000, 1500]
	b.Ingest(makeIOEvent(1, 1000, 500))

	// Sched: thread went back on CPU at t=1500 after being off for 400ns → off from [1100, 1500]
	// This overlaps with the IO window
	b.Ingest(makeSchedEvent(1, 1500, 400))

	capture := b.Build()

	io := capture.Threads[0].IoEvents[0]
	sched := capture.Threads[0].SchedEvents[0]

	if io.CausedSchedEventIdx != 0 {
		t.Errorf("IO.CausedSchedEventIdx = %d, want 0", io.CausedSchedEventIdx)
	}
	if sched.CausedByIoIdx != 0 {
		t.Errorf("Sched.CausedByIoIdx = %d, want 0", sched.CausedByIoIdx)
	}
	if sched.Reason != pb.OffCPUReason_OFF_CPU_IO_BLOCKED {
		t.Errorf("Sched.Reason = %v, want OFF_CPU_IO_BLOCKED", sched.Reason)
	}
}

func TestThreadStateDeriv(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// Sched events: thread was off-CPU twice
	// Off-CPU from [900, 1000] (100ns)
	b.Ingest(makeSchedEvent(1, 1000, 100))
	// Off-CPU from [2000, 2500] (500ns)
	b.Ingest(makeSchedEvent(1, 2500, 500))

	capture := b.Build()

	states := capture.Threads[0].States
	if len(states) < 3 {
		t.Fatalf("states = %d, want >= 3", len(states))
	}

	// First: off-CPU [900, 1000]
	if states[0].State != pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN {
		t.Errorf("state[0] = %v, want OFF_CPU_UNKNOWN", states[0].State)
	}
	if states[0].StartNs != 900 || states[0].EndNs != 1000 {
		t.Errorf("state[0] range = [%d, %d], want [900, 1000]", states[0].StartNs, states[0].EndNs)
	}

	// Second: running [1000, 2000]
	if states[1].State != pb.ThreadState_THREAD_STATE_RUNNING {
		t.Errorf("state[1] = %v, want RUNNING", states[1].State)
	}
	if states[1].StartNs != 1000 || states[1].EndNs != 2000 {
		t.Errorf("state[1] range = [%d, %d], want [1000, 2000]", states[1].StartNs, states[1].EndNs)
	}

	// Third: off-CPU [2000, 2500]
	if states[2].State != pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN {
		t.Errorf("state[2] = %v, want OFF_CPU_UNKNOWN", states[2].State)
	}
}

func TestIOSchedCrossRefUpdatesState(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// IO read at t=1000, latency=500ns → [1000, 1500]
	b.Ingest(makeIOEvent(1, 1000, 500))
	// Off-CPU at [1100, 1500] → overlaps with IO
	b.Ingest(makeSchedEvent(1, 1500, 400))

	capture := b.Build()

	// The derived state should show OFF_CPU_IO (not OFF_CPU_UNKNOWN)
	// because the cross-ref identified the IO cause
	found := false
	for _, s := range capture.Threads[0].States {
		if s.State == pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OFF_CPU_IO state from IO↔sched cross-ref")
	}
}

func TestProtoRoundTrip(t *testing.T) {
	b := NewBuilder("test-app", "host1", 1234, 99)

	frames := []collector.InlineFrame{
		{Label: "foo", Path: "foo.rb", Line: 42},
	}
	b.Ingest(makeSampleEvent(100, 1_000_000, frames))
	b.Ingest(makeIOEvent(100, 2_000_000, 500))
	b.Ingest(makeSchedEvent(100, 3_000_000, 1000))

	capture := b.Build()

	// Serialize
	data, err := proto.Marshal(capture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized to empty bytes")
	}

	// Deserialize
	var cap2 pb.Capture
	if err := proto.Unmarshal(data, &cap2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify round-trip
	if cap2.Header.Version != 2 {
		t.Errorf("round-trip version = %d", cap2.Header.Version)
	}
	if len(cap2.Threads) != 1 {
		t.Fatalf("round-trip threads = %d", len(cap2.Threads))
	}
	tl := cap2.Threads[0]
	if tl.ThreadId != 100 {
		t.Errorf("round-trip tid = %d", tl.ThreadId)
	}
	if len(tl.Samples) != 1 {
		t.Errorf("round-trip samples = %d", len(tl.Samples))
	}
	if len(tl.IoEvents) != 1 {
		t.Errorf("round-trip io events = %d", len(tl.IoEvents))
	}
	if len(tl.SchedEvents) != 1 {
		t.Errorf("round-trip sched events = %d", len(tl.SchedEvents))
	}

	// Verify frame table survived round-trip
	if len(cap2.FrameTable) != 1 {
		t.Fatalf("round-trip frame table = %d", len(cap2.FrameTable))
	}
	frame := cap2.FrameTable[0]
	funcName := cap2.StringTable[frame.FunctionNameIdx]
	fileName := cap2.StringTable[frame.FileNameIdx]
	if funcName != "foo" {
		t.Errorf("round-trip func name = %q", funcName)
	}
	if fileName != "foo.rb" {
		t.Errorf("round-trip file name = %q", fileName)
	}

	t.Logf("Capture serialized to %d bytes", len(data))
}

func TestBuilderReset(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	b.Ingest(makeSampleEvent(1, 100, []collector.InlineFrame{{Label: "a", Path: "a.rb", Line: 1}}))
	cap1 := b.Build()
	if len(cap1.Threads) != 1 {
		t.Fatal("expected 1 thread before reset")
	}

	b.Reset()

	cap2 := b.Build()
	if len(cap2.Threads) != 0 {
		t.Errorf("expected 0 threads after reset, got %d", len(cap2.Threads))
	}
	// String table should be fresh (only empty string)
	if len(cap2.StringTable) != 1 {
		t.Errorf("expected 1 string after reset, got %d", len(cap2.StringTable))
	}
}

func TestNearestSampleIdx(t *testing.T) {
	samples := []*pb.Sample{
		{TimestampNs: 100},
		{TimestampNs: 200},
		{TimestampNs: 300},
		{TimestampNs: 400},
	}

	tests := []struct {
		target uint64
		want   int
	}{
		{50, 0},  // before all → first
		{100, 0}, // exact match
		{149, 0}, // closer to 100
		{151, 1}, // closer to 200
		{250, 1}, // equidistant → prefer left
		{350, 2}, // equidistant → prefer left
		{500, 3}, // after all → last
	}

	for _, tt := range tests {
		got := nearestSampleIdx(samples, tt.target)
		if got != tt.want {
			t.Errorf("nearestSampleIdx(target=%d) = %d, want %d", tt.target, got, tt.want)
		}
	}
}

func TestEmptyCapture(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)
	capture := b.Build()

	if capture.Header.Version != 2 {
		t.Errorf("version = %d", capture.Header.Version)
	}
	if len(capture.Threads) != 0 {
		t.Errorf("threads = %d, want 0", len(capture.Threads))
	}
	if len(capture.StringTable) != 1 { // just the empty string
		t.Errorf("string table = %d, want 1", len(capture.StringTable))
	}
	if len(capture.Categories) == 0 {
		t.Error("expected default categories")
	}
}

func TestBuilderIOEventFdInfo(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Ingest a TCP IO event
	b.Ingest(&collector.IOEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventIO, PID: 1000, TID: 100, Timestamp: 1000,
		},
		FD: 7, Op: collector.IoOpRead, Bytes: 4096, LatencyNs: 2_000_000,
		FdType: 2, SockState: 1,
		LocalPort: 54321, RemotePort: 3306,
		LocalAddr: 0x0100A8C0, RemoteAddr: 0x0100000A,
		TCPStats: &collector.IOTCPStats{
			SrttUs: 500, SndCwnd: 10, TotalRetrans: 3,
			PacketsOut: 5, RcvWnd: 65535,
		},
	})

	capture := b.Build()

	if len(capture.Threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(capture.Threads))
	}
	thread := capture.Threads[0]
	if len(thread.IoEvents) != 1 {
		t.Fatalf("expected 1 IO event, got %d", len(thread.IoEvents))
	}

	ioev := thread.IoEvents[0]

	// Check fd_info_idx is populated and points to a connection string
	if ioev.FdInfoIdx == 0 {
		t.Error("FdInfoIdx should be > 0 (interned connection string)")
	}
	fdInfo := capture.StringTable[ioev.FdInfoIdx]
	if fdInfo != "tcp:192.168.0.1:54321→10.0.0.1:3306" {
		t.Errorf("fd_info string: got %q", fdInfo)
	}

	// Check TCP stats
	if ioev.TcpStats == nil {
		t.Fatal("TcpStats is nil")
	}
	if ioev.TcpStats.SrttUs != 500 {
		t.Errorf("SrttUs: got %d, want 500", ioev.TcpStats.SrttUs)
	}
	if ioev.TcpStats.SndCwnd != 10 {
		t.Errorf("SndCwnd: got %d, want 10", ioev.TcpStats.SndCwnd)
	}

	// Check ports
	if ioev.LocalPort != 54321 {
		t.Errorf("LocalPort: got %d, want 54321", ioev.LocalPort)
	}
	if ioev.RemotePort != 3306 {
		t.Errorf("RemotePort: got %d, want 3306", ioev.RemotePort)
	}
}

func TestBuilderIOEventFileType(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Ingest a file IO event (no socket info)
	b.Ingest(&collector.IOEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventIO, PID: 1000, TID: 100, Timestamp: 2000,
		},
		FD: 3, Op: collector.IoOpRead, Bytes: 512, LatencyNs: 50_000,
		FdType: 1, // FILE
	})

	capture := b.Build()
	thread := capture.Threads[0]
	ioev := thread.IoEvents[0]

	fdInfo := capture.StringTable[ioev.FdInfoIdx]
	if fdInfo != "file" {
		t.Errorf("fd_info for file: got %q, want %q", fdInfo, "file")
	}
	if ioev.TcpStats != nil {
		t.Errorf("TcpStats should be nil for file, got %+v", ioev.TcpStats)
	}
}

func TestBuilder_GVLEvents(t *testing.T) {
	b := NewBuilder("test", "host", 1234, 99)

	// Ingest GVL wait events
	b.Ingest(&collector.GVLWaitEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLWait, PID: 1234, TID: 100},
		WaitNs:      5_000_000,
		TimestampNs: 2_000_000,
		ThreadValue: 42,
	})
	b.Ingest(&collector.GVLWaitEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLWait, PID: 1234, TID: 100},
		WaitNs:      3_000_000,
		TimestampNs: 8_000_000,
		ThreadValue: 42,
	})

	capture := b.Build()

	// Find thread 100
	var thread *pb.ThreadTimeline
	for _, tl := range capture.Threads {
		if tl.ThreadId == 100 {
			thread = tl
			break
		}
	}
	if thread == nil {
		t.Fatal("thread 100 not found")
	}

	if len(thread.GvlEvents) != 2 {
		t.Fatalf("expected 2 GVL events, got %d", len(thread.GvlEvents))
	}

	// Should be sorted by timestamp
	if thread.GvlEvents[0].TimestampNs != 2_000_000 {
		t.Errorf("first event timestamp: got %d", thread.GvlEvents[0].TimestampNs)
	}
	if thread.GvlEvents[0].WaitNs != 5_000_000 {
		t.Errorf("first event wait_ns: got %d", thread.GvlEvents[0].WaitNs)
	}
	if thread.GvlEvents[1].TimestampNs != 8_000_000 {
		t.Errorf("second event timestamp: got %d", thread.GvlEvents[1].TimestampNs)
	}
}
