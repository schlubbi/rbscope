package timeline

import (
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func TestCrossRefIOToSamplesEmpty(_ *testing.T) {
	tb := &threadBuilder{}
	tb.ioEvents = []*pb.IOEvent{{TimestampNs: 100}}
	// No samples — should not panic
	crossRefIOToSamples(tb)
}

func TestCrossRefIOToSamplesMultiple(t *testing.T) {
	tb := &threadBuilder{
		samples: []*pb.Sample{
			{TimestampNs: 100},
			{TimestampNs: 200},
			{TimestampNs: 300},
			{TimestampNs: 400},
		},
		ioEvents: []*pb.IOEvent{
			{TimestampNs: 50},  // before all → nearest is 0
			{TimestampNs: 160}, // closer to 200 → nearest is 1
			{TimestampNs: 350}, // equidistant 300/400 → prefers left = 2
			{TimestampNs: 500}, // after all → nearest is 3
		},
	}
	crossRefIOToSamples(tb)

	want := []uint32{0, 1, 2, 3}
	for i, io := range tb.ioEvents {
		if io.NearestSampleIdx != want[i] {
			t.Errorf("io[%d].NearestSampleIdx = %d, want %d", i, io.NearestSampleIdx, want[i])
		}
	}
}

func TestCrossRefIOToSchedNoOverlap(t *testing.T) {
	tb := &threadBuilder{
		ioEvents: []*pb.IOEvent{
			{TimestampNs: 100, LatencyNs: 50}, // IO window [100, 150]
		},
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 300, OffCpuNs: 50}, // off-CPU [250, 300] — no overlap
		},
	}
	crossRefIOToSched(tb)

	if tb.schedEvents[0].Reason != pb.OffCPUReason_OFF_CPU_UNKNOWN {
		t.Errorf("reason = %v, want OFF_CPU_UNKNOWN", tb.schedEvents[0].Reason)
	}
}

func TestCrossRefIOToSchedOverlap(t *testing.T) {
	tb := &threadBuilder{
		ioEvents: []*pb.IOEvent{
			{TimestampNs: 100, LatencyNs: 200}, // IO window [100, 300]
		},
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 250, OffCpuNs: 100}, // off-CPU [150, 250] — overlaps
		},
	}
	crossRefIOToSched(tb)

	if tb.ioEvents[0].CausedSchedEventIdx != 0 {
		t.Errorf("IO.CausedSchedEventIdx = %d, want 0", tb.ioEvents[0].CausedSchedEventIdx)
	}
	if tb.schedEvents[0].CausedByIoIdx != 0 {
		t.Errorf("Sched.CausedByIoIdx = %d, want 0", tb.schedEvents[0].CausedByIoIdx)
	}
	if tb.schedEvents[0].Reason != pb.OffCPUReason_OFF_CPU_IO_BLOCKED {
		t.Errorf("reason = %v, want OFF_CPU_IO_BLOCKED", tb.schedEvents[0].Reason)
	}
}

func TestCrossRefIOToSchedMultipleIOs(t *testing.T) {
	tb := &threadBuilder{
		ioEvents: []*pb.IOEvent{
			{TimestampNs: 100, LatencyNs: 50},  // [100, 150] — no overlap
			{TimestampNs: 200, LatencyNs: 200}, // [200, 400] — overlaps sched
		},
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 350, OffCpuNs: 100}, // off-CPU [250, 350]
		},
	}
	crossRefIOToSched(tb)

	// Only the second IO should match
	if tb.ioEvents[0].CausedSchedEventIdx != 0 {
		// Index 0 is default — check that sched doesn't point back to IO[0]
		if tb.schedEvents[0].CausedByIoIdx != 1 {
			t.Errorf("Sched.CausedByIoIdx = %d, want 1", tb.schedEvents[0].CausedByIoIdx)
		}
	}
	if tb.schedEvents[0].Reason != pb.OffCPUReason_OFF_CPU_IO_BLOCKED {
		t.Errorf("reason = %v, want OFF_CPU_IO_BLOCKED", tb.schedEvents[0].Reason)
	}
}

func TestCrossRefEmpty(t *testing.T) {
	tb := &threadBuilder{}
	// Should not panic on empty
	crossRefIOToSamples(tb)
	crossRefIOToSched(tb)
}

func TestDeriveThreadStatesEmpty(t *testing.T) {
	tb := &threadBuilder{}
	states := deriveThreadStates(tb)
	if len(states) != 0 {
		t.Errorf("states = %d, want 0", len(states))
	}
}

func TestDeriveThreadStatesSingleOffCPU(t *testing.T) {
	tb := &threadBuilder{
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 1000, OffCpuNs: 200}, // off-CPU [800, 1000]
		},
	}
	states := deriveThreadStates(tb)

	// Single off-CPU interval, no preceding RUNNING gap
	if len(states) != 1 {
		t.Fatalf("states = %d, want 1", len(states))
	}
	if states[0].State != pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN {
		t.Errorf("state = %v", states[0].State)
	}
	if states[0].StartNs != 800 || states[0].EndNs != 1000 {
		t.Errorf("range = [%d, %d], want [800, 1000]", states[0].StartNs, states[0].EndNs)
	}
}

func TestDeriveThreadStatesRunningGap(t *testing.T) {
	tb := &threadBuilder{
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 1000, OffCpuNs: 100}, // off [900, 1000]
			{TimestampNs: 3000, OffCpuNs: 500}, // off [2500, 3000]
		},
	}
	states := deriveThreadStates(tb)

	// off [900,1000] → running [1000,2500] → off [2500,3000]
	if len(states) != 3 {
		t.Fatalf("states = %d, want 3", len(states))
	}
	if states[0].State != pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN {
		t.Errorf("state[0] = %v, want OFF_CPU_UNKNOWN", states[0].State)
	}
	if states[1].State != pb.ThreadState_THREAD_STATE_RUNNING {
		t.Errorf("state[1] = %v, want RUNNING", states[1].State)
	}
	if states[1].StartNs != 1000 || states[1].EndNs != 2500 {
		t.Errorf("running range = [%d, %d], want [1000, 2500]", states[1].StartNs, states[1].EndNs)
	}
	if states[2].State != pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN {
		t.Errorf("state[2] = %v, want OFF_CPU_UNKNOWN", states[2].State)
	}
}

func TestDeriveThreadStatesWithIOClassification(t *testing.T) {
	tb := &threadBuilder{
		schedEvents: []*pb.SchedEvent{
			{
				TimestampNs: 1000,
				OffCpuNs:    200,
				Reason:      pb.OffCPUReason_OFF_CPU_IO_BLOCKED,
			},
		},
	}
	states := deriveThreadStates(tb)

	if len(states) != 1 {
		t.Fatalf("states = %d, want 1", len(states))
	}
	if states[0].State != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("state = %v, want OFF_CPU_IO", states[0].State)
	}
}

func TestDeriveThreadStatesBackToBack(t *testing.T) {
	// Two off-CPU periods with no gap → no RUNNING interval between them
	tb := &threadBuilder{
		schedEvents: []*pb.SchedEvent{
			{TimestampNs: 1000, OffCpuNs: 500}, // off [500, 1000]
			{TimestampNs: 1500, OffCpuNs: 500}, // off [1000, 1500]
		},
	}
	states := deriveThreadStates(tb)

	// Should be just 2 off-CPU intervals, no RUNNING gap
	if len(states) != 2 {
		t.Fatalf("states = %d, want 2", len(states))
	}
	for _, s := range states {
		if s.State == pb.ThreadState_THREAD_STATE_RUNNING {
			t.Error("unexpected RUNNING state between back-to-back off-CPU")
		}
	}
}

func TestOffCPUReasonToState(t *testing.T) {
	tests := []struct {
		reason pb.OffCPUReason
		want   pb.ThreadState
	}{
		{pb.OffCPUReason_OFF_CPU_UNKNOWN, pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN},
		{pb.OffCPUReason_OFF_CPU_IO_BLOCKED, pb.ThreadState_THREAD_STATE_OFF_CPU_IO},
		{pb.OffCPUReason_OFF_CPU_GVL_WAIT, pb.ThreadState_THREAD_STATE_OFF_CPU_GVL},
		{pb.OffCPUReason_OFF_CPU_MUTEX, pb.ThreadState_THREAD_STATE_OFF_CPU_MUTEX},
		{pb.OffCPUReason_OFF_CPU_VOLUNTARY_SLEEP, pb.ThreadState_THREAD_STATE_OFF_CPU_SLEEP},
		{pb.OffCPUReason_OFF_CPU_PREEMPTED, pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED},
	}
	for _, tt := range tests {
		got := offCPUReasonToState(tt.reason)
		if got != tt.want {
			t.Errorf("offCPUReasonToState(%v) = %v, want %v", tt.reason, got, tt.want)
		}
	}
}

func TestNearestSampleIdxSingleSample(t *testing.T) {
	samples := []*pb.Sample{{TimestampNs: 500}}

	// Any target should return 0
	for _, target := range []uint64{0, 100, 500, 1000} {
		got := nearestSampleIdx(samples, target)
		if got != 0 {
			t.Errorf("nearestSampleIdx(target=%d, single) = %d, want 0", target, got)
		}
	}
}

func TestNearestSampleIdxExactMatch(t *testing.T) {
	samples := []*pb.Sample{
		{TimestampNs: 100},
		{TimestampNs: 200},
		{TimestampNs: 300},
	}
	for i, s := range samples {
		got := nearestSampleIdx(samples, s.TimestampNs)
		if got != i {
			t.Errorf("exact match at %d: got %d, want %d", s.TimestampNs, got, i)
		}
	}
}
