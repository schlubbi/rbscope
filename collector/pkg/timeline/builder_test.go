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
	return makeSchedEventWithState(tid, ts, offCPUNs, 0) // default: TASK_RUNNING (preempted)
}

func makeSchedEventWithState(tid uint32, ts uint64, offCPUNs uint64, prevState uint8) *collector.SchedEvent {
	return &collector.SchedEvent{
		EventHeader: collector.EventHeader{
			Type:      collector.EventSched,
			TID:       tid,
			Timestamp: ts,
		},
		PrevState: prevState,
		OffCPUNs:  offCPUNs,
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

	// First: off-CPU [900, 1000] — preempted (PrevState=0=TASK_RUNNING)
	if states[0].State != pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED {
		t.Errorf("state[0] = %v, want OFF_CPU_PREEMPTED", states[0].State)
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

	// Third: off-CPU [2000, 2500] — preempted
	if states[2].State != pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED {
		t.Errorf("state[2] = %v, want OFF_CPU_PREEMPTED", states[2].State)
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

func TestVoluntarySleepClassifiedAsIdle(t *testing.T) {
	b := NewBuilder("svc", "h", 1, 99)

	// TASK_INTERRUPTIBLE=1 (voluntary sleep, e.g. epoll_wait)
	// without any matching IO event → should be IDLE
	b.Ingest(makeSchedEventWithState(1, 5000, 4000, 1))

	capture := b.Build()

	states := capture.Threads[0].States
	if len(states) == 0 {
		t.Fatal("expected at least 1 state")
	}
	if states[0].State != pb.ThreadState_THREAD_STATE_IDLE {
		t.Errorf("state = %v, want IDLE", states[0].State)
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

func TestBuilder_GVLStateIntervals(t *testing.T) {
	b := NewBuilder("test", "host", 1234, 99)

	// Simulate: thread starts RUNNING, suspends for I/O, stalls waiting for GVL, runs again
	b.Ingest(&collector.GVLStateChangeEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLState, PID: 1234, TID: 100},
		GVLState:    collector.GVLStateRunning,
		TimestampNs: 1_000_000,
		ThreadValue: 42,
	})
	b.Ingest(&collector.GVLStateChangeEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLState, PID: 1234, TID: 100},
		GVLState:    collector.GVLStateSuspended,
		TimestampNs: 5_000_000,
		ThreadValue: 42,
	})
	b.Ingest(&collector.GVLStateChangeEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLState, PID: 1234, TID: 100},
		GVLState:    collector.GVLStateStalled,
		TimestampNs: 8_000_000,
		ThreadValue: 42,
	})
	b.Ingest(&collector.GVLStateChangeEvent{
		EventHeader: collector.EventHeader{Type: collector.EventGVLState, PID: 1234, TID: 100},
		GVLState:    collector.GVLStateRunning,
		TimestampNs: 9_000_000,
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

	// Should have 4 state changes stored
	if len(thread.GvlStateChanges) != 4 {
		t.Fatalf("expected 4 GVL state changes, got %d", len(thread.GvlStateChanges))
	}

	// Should have computed intervals (at least 3: RUNNING, SUSPENDED, STALLED)
	// The 4th (final RUNNING) depends on capture end time
	if len(thread.GvlIntervals) < 3 {
		t.Fatalf("expected at least 3 GVL intervals, got %d", len(thread.GvlIntervals))
	}

	// First interval should be RUNNING
	if thread.GvlIntervals[0].State != pb.GVLState_GVL_STATE_RUNNING {
		t.Errorf("first interval: got %v, want RUNNING", thread.GvlIntervals[0].State)
	}
	// Second should be SUSPENDED
	if thread.GvlIntervals[1].State != pb.GVLState_GVL_STATE_SUSPENDED {
		t.Errorf("second interval: got %v, want SUSPENDED", thread.GvlIntervals[1].State)
	}
	// Third should be STALLED
	if thread.GvlIntervals[2].State != pb.GVLState_GVL_STATE_STALLED {
		t.Errorf("third interval: got %v, want STALLED", thread.GvlIntervals[2].State)
	}
}

func TestShouldFilterNativeFrame(t *testing.T) {
	tests := []struct {
		funcName string
		libPath  string
		isRubyVM bool
		want     bool
		reason   string
	}{
		{"rb_funcall", "/usr/lib/libruby.so", true, true, "Ruby VM frame"},
		{"", "/usr/lib/libc.so", false, true, "empty function name"},
		{"__rbscope_probe_ruby_sample", "/rbscope/gem/lib/rbscope.so", false, true, "rbscope probe"},
		{"__rbscope_probe_gvl_stack", "/rbscope/gem/lib/rbscope.so", false, true, "rbscope GVL probe"},
		{"[anon:Ruby:rb_jit_reserve_addr_space]+0x1234", "[anon:Ruby:rb_jit_reserve_addr_space]", false, true, "JIT region (libPath)"},
		{"0x12345", "[anon:Ruby:rb_jit_reserve_addr_space]", false, true, "JIT region addr"},
		{"_start", "", false, true, "process _start"},
		{"_dl_relocate_object", "/usr/lib/ld-linux.so", false, true, "dynamic linker"},
		{"trilogy_query_send", "/usr/lib/trilogy.so", false, false, "C extension function"},
		{"read", "/usr/lib/libc.so.6", false, false, "libc syscall wrapper"},
		{"__libc_start_main", "/usr/lib/libc.so.6", false, false, "libc main"},
		{"rb_trilogy_query", "/usr/lib/trilogy.so", false, false, "C extension entry"},
		{"get_readers", "/gems/pitchfork_http.so", false, false, "C extension function"},
	}

	for _, tt := range tests {
		got := shouldFilterNativeFrame(tt.funcName, tt.libPath, tt.isRubyVM)
		if got != tt.want {
			t.Errorf("shouldFilterNativeFrame(%q, %q, %v) = %v, want %v (%s)",
				tt.funcName, tt.libPath, tt.isRubyVM, got, tt.want, tt.reason)
		}
	}
}

func TestSynthesizeIOSamples(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Create some Ruby frames in the frame table
	rubyFrame1 := b.frames.Intern("PostsController#index", "app/controllers/posts_controller.rb", 10)
	rubyFrame2 := b.frames.Intern("Trilogy#query", "lib/trilogy.rb", 20)
	// Create native frames (from I/O event)
	nativeFrame1 := b.frames.Intern("rb_trilogy_query", "/usr/lib/trilogy.so", 0)
	nativeFrame2 := b.frames.Intern("write", "/usr/lib/libc.so.6", 0)

	tb := &threadBuilder{}

	// Add a regular Ruby sample (timer-based)
	tb.samples = []*pb.Sample{
		{
			TimestampNs: 1_000_000_000,
			FrameIds:    []uint32{rubyFrame2, rubyFrame1}, // leaf-first
			Weight:      1,
		},
	}

	// Add an I/O event with native frames and Ruby context
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:         1_000_500_000,                        // 500µs after sample
			NativeFrameIds:      []uint32{nativeFrame2, nativeFrame1}, // write → rb_trilogy_query (leaf-first)
			RubyContextFrameIds: []uint32{rubyFrame2, rubyFrame1},     // Trilogy#query → PostsController#index
			NearestSampleIdx:    0,
		},
	}

	b.synthesizeIOSamples(tb)

	// Should now have 2 samples: original + synthetic I/O
	if len(tb.samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(tb.samples))
	}

	// Find the synthetic sample
	var ioSample *pb.Sample
	for _, s := range tb.samples {
		if s.IsIoSample {
			ioSample = s
			break
		}
	}
	if ioSample == nil {
		t.Fatal("no I/O sample found")
	}

	// Synthetic sample should have native + Ruby frames (leaf-first order):
	// [write, rb_trilogy_query, Trilogy#query, PostsController#index]
	expectedFrames := []uint32{nativeFrame2, nativeFrame1, rubyFrame2, rubyFrame1}
	if len(ioSample.FrameIds) != len(expectedFrames) {
		t.Fatalf("I/O sample frame count: got %d, want %d", len(ioSample.FrameIds), len(expectedFrames))
	}
	for i, got := range ioSample.FrameIds {
		if got != expectedFrames[i] {
			t.Errorf("frame[%d]: got %d, want %d", i, got, expectedFrames[i])
		}
	}
	if ioSample.Weight != 1 {
		t.Errorf("weight: got %d, want 1", ioSample.Weight)
	}
}

func TestSynthesizeIOSamples_FallbackToNearestSample(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	rubyFrame := b.frames.Intern("Controller#action", "app/controllers/test.rb", 5)
	nativeFrame := b.frames.Intern("read", "/usr/lib/libc.so.6", 0)

	tb := &threadBuilder{}
	tb.samples = []*pb.Sample{
		{
			TimestampNs: 1_000_000_000,
			FrameIds:    []uint32{rubyFrame}, // only Ruby frames (no native appended)
			Weight:      1,
		},
	}
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:    1_000_050_000, // 50µs after — within 100ms window
			NativeFrameIds: []uint32{nativeFrame},
			// No RubyContextFrameIds — will fall back to nearest sample
			NearestSampleIdx: 0,
		},
	}

	b.synthesizeIOSamples(tb)

	if len(tb.samples) != 2 {
		t.Fatalf("expected 2 samples (original + synthetic), got %d", len(tb.samples))
	}

	var ioSample *pb.Sample
	for _, s := range tb.samples {
		if s.IsIoSample {
			ioSample = s
			break
		}
	}
	if ioSample == nil {
		t.Fatal("no I/O sample found via nearest-sample fallback")
	}
	// Should have [read, Controller#action]
	if len(ioSample.FrameIds) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(ioSample.FrameIds))
	}
}

func TestSynthesizeIOSamples_NoNativeFrames(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	rubyFrame := b.frames.Intern("foo", "test.rb", 1)

	tb := &threadBuilder{}
	tb.samples = []*pb.Sample{
		{TimestampNs: 1_000_000_000, FrameIds: []uint32{rubyFrame}, Weight: 1},
	}
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:         1_000_050_000,
			RubyContextFrameIds: []uint32{rubyFrame},
			// No NativeFrameIds — should not create synthetic sample
		},
	}

	b.synthesizeIOSamples(tb)

	// Should still be just 1 sample (no synthesis without native frames)
	if len(tb.samples) != 1 {
		t.Fatalf("expected 1 sample (no synthesis), got %d", len(tb.samples))
	}
}

func TestSynthesizeIOSamples_TooFarApart(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	rubyFrame := b.frames.Intern("foo", "test.rb", 1)
	nativeFrame := b.frames.Intern("write", "/usr/lib/libc.so.6", 0)

	tb := &threadBuilder{}
	tb.samples = []*pb.Sample{
		{TimestampNs: 1_000_000_000, FrameIds: []uint32{rubyFrame}, Weight: 1},
	}
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:      1_200_000_000, // 200ms later — beyond 100ms window
			NativeFrameIds:   []uint32{nativeFrame},
			NearestSampleIdx: 0,
			// No RubyContextFrameIds
		},
	}

	b.synthesizeIOSamples(tb)

	// Should still be just 1 sample (too far apart, no SUSPENDED context)
	if len(tb.samples) != 1 {
		t.Fatalf("expected 1 sample (too far apart), got %d", len(tb.samples))
	}
}

func TestExtractRubyFrameIDs(t *testing.T) {
	st := newStringTable()
	ft := newFrameTable(st)

	rubyFrame1 := ft.Intern("Controller#index", "app/controllers.rb", 10)
	rubyFrame2 := ft.Intern("AR#query", "activerecord.rb", 20)
	nativeFrame := ft.Intern("trilogy_query", "/usr/lib/trilogy.so", 0)

	mixed := []uint32{nativeFrame, rubyFrame1, rubyFrame2}
	result := extractRubyFrameIDs(mixed, ft)

	if len(result) != 2 {
		t.Fatalf("expected 2 Ruby frames, got %d", len(result))
	}
	if result[0] != rubyFrame1 || result[1] != rubyFrame2 {
		t.Errorf("wrong Ruby frames: got %v, want [%d, %d]", result, rubyFrame1, rubyFrame2)
	}
}

func TestFindSuspendedStack(t *testing.T) {
	mkStack := func(ts uint64) *collector.GVLStackEvent {
		return &collector.GVLStackEvent{TimestampNs: ts}
	}

	stacks := []*collector.GVLStackEvent{
		mkStack(1_000_000_000), // 1s
		mkStack(1_010_000_000), // 1.01s
		mkStack(1_050_000_000), // 1.05s
		mkStack(1_200_000_000), // 1.2s
	}

	t.Run("exact match", func(t *testing.T) {
		got := findSuspendedStack(stacks, 1_050_000_000)
		if got == nil || got.TimestampNs != 1_050_000_000 {
			t.Errorf("expected stack at 1.05s, got %v", got)
		}
	})

	t.Run("between stacks picks earlier", func(t *testing.T) {
		got := findSuspendedStack(stacks, 1_030_000_000) // between 1.01s and 1.05s
		if got == nil || got.TimestampNs != 1_010_000_000 {
			t.Errorf("expected stack at 1.01s, got %v", got)
		}
	})

	t.Run("before all stacks", func(t *testing.T) {
		got := findSuspendedStack(stacks, 999_000_000) // before first stack
		if got != nil {
			t.Errorf("expected nil, got ts=%d", got.TimestampNs)
		}
	})

	t.Run("after all stacks within window", func(t *testing.T) {
		got := findSuspendedStack(stacks, 1_250_000_000) // 50ms after last
		if got == nil || got.TimestampNs != 1_200_000_000 {
			t.Errorf("expected stack at 1.2s, got %v", got)
		}
	})

	t.Run("after all stacks beyond window", func(t *testing.T) {
		got := findSuspendedStack(stacks, 1_500_000_000) // 300ms after last
		if got != nil {
			t.Errorf("expected nil (beyond 100ms window), got ts=%d", got.TimestampNs)
		}
	})

	t.Run("empty stacks", func(t *testing.T) {
		got := findSuspendedStack(nil, 1_000_000_000)
		if got != nil {
			t.Errorf("expected nil for empty stacks, got %v", got)
		}
	})

	t.Run("single stack within window", func(t *testing.T) {
		single := []*collector.GVLStackEvent{mkStack(1_000_000_000)}
		got := findSuspendedStack(single, 1_005_000_000) // 5ms later
		if got == nil || got.TimestampNs != 1_000_000_000 {
			t.Errorf("expected stack at 1s, got %v", got)
		}
	})
}

func TestParseAndInternSuspendedStack(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	frames := []collector.InlineFrame{
		{Label: "Trilogy#query", Path: "(unknown)", Line: 0},
		{Label: "PostsController#index", Path: "app/controllers/posts_controller.rb", Line: 10},
	}
	data := makeStackData(frames)
	ids := b.parseAndInternSuspendedStack(data)

	if len(ids) != 2 {
		t.Fatalf("expected 2 frame IDs, got %d", len(ids))
	}

	// Verify frames were interned with correct names
	f0 := b.frames.table[ids[0]]
	if b.strings.Lookup(f0.FunctionNameIdx) != "Trilogy#query" {
		t.Errorf("frame[0] name = %q, want Trilogy#query", b.strings.Lookup(f0.FunctionNameIdx))
	}
	f1 := b.frames.table[ids[1]]
	if b.strings.Lookup(f1.FunctionNameIdx) != "PostsController#index" {
		t.Errorf("frame[1] name = %q, want PostsController#index", b.strings.Lookup(f1.FunctionNameIdx))
	}

	t.Run("empty data", func(t *testing.T) {
		ids := b.parseAndInternSuspendedStack(nil)
		if ids != nil {
			t.Errorf("expected nil for empty data, got %v", ids)
		}
	})

	t.Run("idempotent interning", func(t *testing.T) {
		ids2 := b.parseAndInternSuspendedStack(data)
		if ids[0] != ids2[0] || ids[1] != ids2[1] {
			t.Errorf("second parse returned different IDs: %v vs %v", ids, ids2)
		}
	})
}

func TestCorrelateIOWithSuspendedStacks(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)
	tid := uint32(100)

	trilogyFrames := []collector.InlineFrame{
		{Label: "Trilogy#query", Path: "(unknown)", Line: 0},
		{Label: "PostsController#index", Path: "app/controllers/posts_controller.rb", Line: 10},
	}
	httpFrames := []collector.InlineFrame{
		{Label: "IO#readpartial", Path: "(unknown)", Line: 0},
		{Label: "Pitchfork::HttpParser#read", Path: "pitchfork/http_parser.rb", Line: 5},
	}

	b.suspendedStacks[tid] = []*collector.GVLStackEvent{
		{TimestampNs: 1_050_000_000, StackData: makeStackData(httpFrames)},
		{TimestampNs: 1_000_000_000, StackData: makeStackData(trilogyFrames)},
		// Intentionally out of order — correlate should sort
	}

	tb := &threadBuilder{}
	tb.ioEvents = []*pb.IOEvent{
		{TimestampNs: 1_005_000_000}, // 5ms after trilogy stack
		{TimestampNs: 1_055_000_000}, // 5ms after http stack
	}

	b.correlateIOWithSuspendedStacks(tid, tb)

	// First IO event should match the Trilogy SUSPENDED stack
	if len(tb.ioEvents[0].RubyContextFrameIds) == 0 {
		t.Fatal("IO event[0] should have Ruby context from Trilogy SUSPENDED stack")
	}
	leaf0 := b.strings.Lookup(b.frames.table[tb.ioEvents[0].RubyContextFrameIds[0]].FunctionNameIdx)
	if leaf0 != "Trilogy#query" {
		t.Errorf("IO event[0] leaf = %q, want Trilogy#query", leaf0)
	}

	// Second IO event should match the HTTP SUSPENDED stack
	if len(tb.ioEvents[1].RubyContextFrameIds) == 0 {
		t.Fatal("IO event[1] should have Ruby context from HTTP SUSPENDED stack")
	}
	leaf1 := b.strings.Lookup(b.frames.table[tb.ioEvents[1].RubyContextFrameIds[0]].FunctionNameIdx)
	if leaf1 != "IO#readpartial" {
		t.Errorf("IO event[1] leaf = %q, want IO#readpartial", leaf1)
	}

	t.Run("no stacks for TID", func(t *testing.T) {
		tb2 := &threadBuilder{}
		tb2.ioEvents = []*pb.IOEvent{{TimestampNs: 1_000_000_000}}
		b.correlateIOWithSuspendedStacks(999, tb2) // different TID
		if len(tb2.ioEvents[0].RubyContextFrameIds) != 0 {
			t.Error("expected no Ruby context for unknown TID")
		}
	})
}

func TestHasExtensionFrames(t *testing.T) {
	st := newStringTable()
	ft := newFrameTable(st)

	libcFrame := ft.Intern("write", "/usr/lib/libc.so.6", 0)
	trilogyFrame := ft.Intern("rb_trilogy_query", "/gems/trilogy-2.11/lib/trilogy/cext.so", 0)
	ldFrame := ft.Intern("_dl_start", "/lib/ld-linux-aarch64.so.1", 0)

	t.Run("libc only", func(t *testing.T) {
		if hasExtensionFrames([]uint32{libcFrame, ldFrame}, ft) {
			t.Error("libc + ld-linux should NOT count as extension frames")
		}
	})

	t.Run("with C extension", func(t *testing.T) {
		if !hasExtensionFrames([]uint32{libcFrame, trilogyFrame}, ft) {
			t.Error("trilogy.so SHOULD count as extension frame")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if hasExtensionFrames(nil, ft) {
			t.Error("empty frame list should return false")
		}
	})

	t.Run("libpthread", func(t *testing.T) {
		pthreadFrame := ft.Intern("pthread_mutex_lock", "/usr/lib/libpthread.so.0", 0)
		if hasExtensionFrames([]uint32{pthreadFrame}, ft) {
			t.Error("libpthread should NOT count as extension frame")
		}
	})
}

func TestIsPlausibleIOContext(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	trilogyRuby := b.frames.Intern("Trilogy#query", "(unknown)", 0)
	ioReadpartial := b.frames.Intern("IO#readpartial", "(unknown)", 0)
	controllerFrame := b.frames.Intern("PostsController#index", "app/controllers/posts_controller.rb", 10)
	idleFrame := b.frames.Intern("Pitchfork::Waiter#get_readers", "(unknown)", 0)
	sleepFrame := b.frames.Intern("Kernel#sleep", "(unknown)", 0)

	trilogyNative := b.frames.Intern("rb_trilogy_query", "/gems/trilogy/cext.so", 0)
	libcWrite := b.frames.Intern("write", "/usr/lib/libc.so.6", 0)

	t.Run("Trilogy ruby + Trilogy native = plausible", func(t *testing.T) {
		if !b.isPlausibleIOContext(
			[]uint32{trilogyRuby, controllerFrame},
			[]uint32{libcWrite, trilogyNative},
		) {
			t.Error("Trilogy#query with Trilogy native frames should be plausible")
		}
	})

	t.Run("idle frame = not plausible", func(t *testing.T) {
		if b.isPlausibleIOContext(
			[]uint32{idleFrame},
			[]uint32{libcWrite},
		) {
			t.Error("idle get_readers frame should NOT be plausible")
		}
	})

	t.Run("Kernel#sleep = not plausible", func(t *testing.T) {
		if b.isPlausibleIOContext(
			[]uint32{sleepFrame},
			[]uint32{libcWrite},
		) {
			t.Error("Kernel#sleep frame should NOT be plausible")
		}
	})

	t.Run("IO#readpartial + extension native = not plausible", func(t *testing.T) {
		if b.isPlausibleIOContext(
			[]uint32{ioReadpartial, controllerFrame},
			[]uint32{libcWrite, trilogyNative},
		) {
			t.Error("generic IO#readpartial with extension native frames should NOT be plausible")
		}
	})

	t.Run("IO#readpartial + libc only = plausible", func(t *testing.T) {
		if !b.isPlausibleIOContext(
			[]uint32{ioReadpartial, controllerFrame},
			[]uint32{libcWrite},
		) {
			t.Error("IO#readpartial with plain libc write should be plausible (no extension mismatch)")
		}
	})

	t.Run("empty ruby frames = not plausible", func(t *testing.T) {
		if b.isPlausibleIOContext(nil, []uint32{libcWrite}) {
			t.Error("empty Ruby frames should NOT be plausible")
		}
	})
}

func TestSynthesizeIOSamples_PlausibilityRejection(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Ruby context from HTTP I/O, but native stack from Trilogy
	httpLeaf := b.frames.Intern("IO#readpartial", "(unknown)", 0)
	controllerFrame := b.frames.Intern("PostsController#index", "app/controllers/posts_controller.rb", 10)
	trilogyNative := b.frames.Intern("rb_trilogy_query", "/gems/trilogy/cext.so", 0)
	libcRead := b.frames.Intern("read", "/usr/lib/libc.so.6", 0)

	tb := &threadBuilder{}
	tb.samples = []*pb.Sample{
		{TimestampNs: 1_000_000_000, FrameIds: []uint32{httpLeaf, controllerFrame}, Weight: 1},
	}
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:         1_000_500_000,
			NativeFrameIds:      []uint32{libcRead, trilogyNative},
			RubyContextFrameIds: []uint32{httpLeaf, controllerFrame}, // mismatched!
			NearestSampleIdx:    0,
		},
	}

	b.synthesizeIOSamples(tb)

	// Should NOT synthesize — IO#readpartial context doesn't match Trilogy native stack
	ioSamples := 0
	for _, s := range tb.samples {
		if s.IsIoSample {
			ioSamples++
		}
	}
	if ioSamples != 0 {
		t.Errorf("expected 0 synthesized samples (plausibility rejected), got %d", ioSamples)
	}
}

func TestSynthesizeIOSamples_FallbackAlsoChecksPlausibility(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Nearest timer sample has Trilogy#query — should pass plausibility for Trilogy native
	trilogyRuby := b.frames.Intern("Trilogy#query", "(unknown)", 0)
	controllerFrame := b.frames.Intern("PostsController#index", "app/controllers/posts_controller.rb", 10)
	trilogyNative := b.frames.Intern("rb_trilogy_query", "/gems/trilogy/cext.so", 0)
	libcRead := b.frames.Intern("read", "/usr/lib/libc.so.6", 0)

	tb := &threadBuilder{}
	tb.samples = []*pb.Sample{
		{TimestampNs: 1_000_000_000, FrameIds: []uint32{trilogyRuby, controllerFrame}, Weight: 1},
	}
	tb.ioEvents = []*pb.IOEvent{
		{
			TimestampNs:    1_000_500_000,
			NativeFrameIds: []uint32{libcRead, trilogyNative},
			// No RubyContextFrameIds — falls back to nearest sample
			NearestSampleIdx: 0,
		},
	}

	b.synthesizeIOSamples(tb)

	ioSamples := 0
	for _, s := range tb.samples {
		if s.IsIoSample {
			ioSamples++
		}
	}
	if ioSamples != 1 {
		t.Fatalf("expected 1 synthesized sample via fallback, got %d", ioSamples)
	}
}

func TestBuilder_IngestAllocEvent(t *testing.T) {
	b := NewBuilder("test", "host1", 100, 99)

	stackData := makeStackData([]collector.InlineFrame{
		{Label: "Object.new", Path: "test.rb", Line: 5},
		{Label: "PostsController#index", Path: "app/controllers/posts_controller.rb", Line: 10},
	})

	b.Ingest(&collector.RubyAllocEvent{
		RubySampleEvent: collector.RubySampleEvent{
			EventHeader:  collector.EventHeader{TID: 100, PID: 100, Timestamp: 1000000},
			Weight:       1,
			StackData:    stackData,
			StackDataLen: uint32(len(stackData)),
		},
		ObjectType: "String",
		SizeBytes:  40,
	})

	b.Ingest(&collector.RubyAllocEvent{
		RubySampleEvent: collector.RubySampleEvent{
			EventHeader:  collector.EventHeader{TID: 100, PID: 100, Timestamp: 2000000},
			Weight:       1,
			StackData:    stackData,
			StackDataLen: uint32(len(stackData)),
		},
		ObjectType: "Array",
		SizeBytes:  80,
	})

	capture := b.Build()

	if len(capture.Threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(capture.Threads))
	}

	thread := capture.Threads[0]
	if len(thread.Allocations) != 2 {
		t.Fatalf("expected 2 allocations, got %d", len(thread.Allocations))
	}

	alloc0 := thread.Allocations[0]
	if alloc0.SizeBytes != 40 {
		t.Errorf("alloc[0] size: got %d, want 40", alloc0.SizeBytes)
	}
	typeName := capture.StringTable[alloc0.ObjectTypeIdx]
	if typeName != "String" {
		t.Errorf("alloc[0] type: got %q, want %q", typeName, "String")
	}
	if len(alloc0.FrameIds) != 2 {
		t.Errorf("alloc[0] frames: got %d, want 2", len(alloc0.FrameIds))
	}

	alloc1 := thread.Allocations[1]
	if alloc1.SizeBytes != 80 {
		t.Errorf("alloc[1] size: got %d, want 80", alloc1.SizeBytes)
	}

	if len(thread.Samples) != 0 {
		t.Errorf("expected 0 CPU samples, got %d", len(thread.Samples))
	}
}

func TestShortenRubyPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// Gem paths
		{"/app/vendor/bundle/ruby/4.0.0/gems/rack-3.2.5/lib/rack/logger.rb", "rack/logger.rb"},
		{"/vendor/bundle/ruby/4.0.0/gems/railties-8.1.3/lib/rails/engine.rb", "rails/engine.rb"},
		{"/gems/bundler-4.0.9/exe/bundle", "exe/bundle"},
		// Ruby stdlib
		{"/opt/ruby-4.0/lib/ruby/4.0.0/net/http.rb", "net/http.rb"},
		{"/opt/ruby-4.0/lib/ruby/4.0.0/rubygems.rb", "rubygems.rb"},
		// App paths
		{"/rbscope/test-rails-app/app/controllers/posts_controller.rb", "app/controllers/posts_controller.rb"},
		{"/rbscope/test-rails-app/config/routes.rb", "config/routes.rb"},
		// Empty
		{"", ""},
		// Already short
		{"rack/logger.rb", "rack/logger.rb"},
	}

	for _, tt := range tests {
		got := shortenRubyPath(tt.in)
		if got != tt.want {
			t.Errorf("shortenRubyPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestQualifyMethodName(t *testing.T) {
	tests := []struct {
		name, path, want string
	}{
		{"call", "rack/logger.rb", "call [rack/logger]"},
		{"call", "rack/lint.rb", "call [rack/lint]"},
		{"block in call", "rack/events.rb", "block in call [rack/events]"},
		{"index", "app/controllers/posts_controller.rb", "index"}, // not ambiguous
		{"process_action", "action_controller/metal.rb", "process_action"},
		{"call", "", "call"}, // no path, leave as-is
		{"new", "active_record/base.rb", "new [active_record/base]"},
	}

	for _, tt := range tests {
		got := qualifyMethodName(tt.name, tt.path)
		if got != tt.want {
			t.Errorf("qualifyMethodName(%q, %q) = %q, want %q", tt.name, tt.path, got, tt.want)
		}
	}
}
