package timeline

import (
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func TestComputeGVLIntervals_BasicCycle(t *testing.T) {
	changes := []*pb.GVLStateChange{
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 5000, State: pb.GVLState_GVL_STATE_SUSPENDED},
		{TimestampNs: 8000, State: pb.GVLState_GVL_STATE_STALLED},
		{TimestampNs: 9000, State: pb.GVLState_GVL_STATE_RUNNING},
	}

	intervals := computeGVLIntervals(changes, 10000)

	if len(intervals) != 4 {
		t.Fatalf("expected 4 intervals, got %d", len(intervals))
	}

	// RUNNING 1000-5000
	assertInterval(t, intervals[0], 1000, 5000, pb.GVLState_GVL_STATE_RUNNING)
	// SUSPENDED 5000-8000
	assertInterval(t, intervals[1], 5000, 8000, pb.GVLState_GVL_STATE_SUSPENDED)
	// STALLED 8000-9000
	assertInterval(t, intervals[2], 8000, 9000, pb.GVLState_GVL_STATE_STALLED)
	// RUNNING 9000-10000 (capped at capture end)
	assertInterval(t, intervals[3], 9000, 10000, pb.GVLState_GVL_STATE_RUNNING)
}

func TestComputeGVLIntervals_Empty(t *testing.T) {
	intervals := computeGVLIntervals(nil, 10000)
	if intervals != nil {
		t.Fatalf("expected nil for empty input, got %d intervals", len(intervals))
	}
}

func TestComputeGVLIntervals_SingleEvent(t *testing.T) {
	changes := []*pb.GVLStateChange{
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
	}

	intervals := computeGVLIntervals(changes, 5000)

	if len(intervals) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(intervals))
	}
	assertInterval(t, intervals[0], 1000, 5000, pb.GVLState_GVL_STATE_RUNNING)
}

func TestComputeGVLIntervals_DuplicateConsecutive(t *testing.T) {
	changes := []*pb.GVLStateChange{
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 2000, State: pb.GVLState_GVL_STATE_RUNNING}, // duplicate
		{TimestampNs: 5000, State: pb.GVLState_GVL_STATE_SUSPENDED},
	}

	intervals := computeGVLIntervals(changes, 10000)

	if len(intervals) != 2 {
		t.Fatalf("expected 2 intervals (duplicate merged), got %d", len(intervals))
	}
	assertInterval(t, intervals[0], 1000, 5000, pb.GVLState_GVL_STATE_RUNNING)
	assertInterval(t, intervals[1], 5000, 10000, pb.GVLState_GVL_STATE_SUSPENDED)
}

func TestComputeGVLIntervals_StartWithResumed(t *testing.T) {
	// Thread was already running when we started observing — first event is RESUMED
	changes := []*pb.GVLStateChange{
		{TimestampNs: 500, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 3000, State: pb.GVLState_GVL_STATE_STALLED},
		{TimestampNs: 3500, State: pb.GVLState_GVL_STATE_RUNNING},
	}

	intervals := computeGVLIntervals(changes, 5000)

	if len(intervals) != 3 {
		t.Fatalf("expected 3 intervals, got %d", len(intervals))
	}
	assertInterval(t, intervals[0], 500, 3000, pb.GVLState_GVL_STATE_RUNNING)
	assertInterval(t, intervals[1], 3000, 3500, pb.GVLState_GVL_STATE_STALLED)
	assertInterval(t, intervals[2], 3500, 5000, pb.GVLState_GVL_STATE_RUNNING)
}

func TestComputeGVLIntervals_NoContention(t *testing.T) {
	// Single-threaded app: only RUNNING and SUSPENDED, no STALLED
	changes := []*pb.GVLStateChange{
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 4000, State: pb.GVLState_GVL_STATE_SUSPENDED},
		{TimestampNs: 5000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 8000, State: pb.GVLState_GVL_STATE_SUSPENDED},
		{TimestampNs: 9000, State: pb.GVLState_GVL_STATE_RUNNING},
	}

	intervals := computeGVLIntervals(changes, 10000)

	if len(intervals) != 5 {
		t.Fatalf("expected 5 intervals, got %d", len(intervals))
	}
	// No STALLED intervals at all
	for _, iv := range intervals {
		if iv.State == pb.GVLState_GVL_STATE_STALLED {
			t.Errorf("unexpected STALLED interval in single-threaded scenario")
		}
	}
}

func TestComputeGVLIntervals_Unsorted(t *testing.T) {
	// Input not sorted — should still produce correct intervals
	changes := []*pb.GVLStateChange{
		{TimestampNs: 5000, State: pb.GVLState_GVL_STATE_SUSPENDED},
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 8000, State: pb.GVLState_GVL_STATE_RUNNING},
	}

	intervals := computeGVLIntervals(changes, 10000)

	if len(intervals) != 3 {
		t.Fatalf("expected 3 intervals, got %d", len(intervals))
	}
	assertInterval(t, intervals[0], 1000, 5000, pb.GVLState_GVL_STATE_RUNNING)
	assertInterval(t, intervals[1], 5000, 8000, pb.GVLState_GVL_STATE_SUSPENDED)
	assertInterval(t, intervals[2], 8000, 10000, pb.GVLState_GVL_STATE_RUNNING)
}

func TestComputeGVLIntervals_NoCaptureEnd(t *testing.T) {
	changes := []*pb.GVLStateChange{
		{TimestampNs: 1000, State: pb.GVLState_GVL_STATE_RUNNING},
		{TimestampNs: 5000, State: pb.GVLState_GVL_STATE_SUSPENDED},
	}

	// captureEndNs = 0 → last interval should end at last event timestamp
	intervals := computeGVLIntervals(changes, 0)

	if len(intervals) != 1 {
		t.Fatalf("expected 1 interval (last has zero width), got %d", len(intervals))
	}
	assertInterval(t, intervals[0], 1000, 5000, pb.GVLState_GVL_STATE_RUNNING)
}

func assertInterval(t *testing.T, iv *pb.GVLStateInterval, startNs, endNs uint64, state pb.GVLState) {
	t.Helper()
	if iv.StartNs != startNs {
		t.Errorf("start: got %d, want %d", iv.StartNs, startNs)
	}
	if iv.EndNs != endNs {
		t.Errorf("end: got %d, want %d", iv.EndNs, endNs)
	}
	if iv.State != state {
		t.Errorf("state: got %v, want %v", iv.State, state)
	}
}
