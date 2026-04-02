package timeline

import (
	"sort"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// computeGVLIntervals converts sorted GVL state changes into continuous
// non-overlapping intervals. Each interval represents a period in one
// GVL state (RUNNING, STALLED, or SUSPENDED).
//
// Rules:
//   - Each state change starts a new interval and closes the previous one
//   - Duplicate consecutive states are skipped
//   - The first event starts at its own timestamp (no synthetic pre-history)
//   - The last interval is capped at captureEndNs
//   - If captureEndNs == 0, the last interval ends at the last event timestamp
func computeGVLIntervals(changes []*pb.GVLStateChange, captureEndNs uint64) []*pb.GVLStateInterval {
	if len(changes) == 0 {
		return nil
	}

	// Sort by timestamp (should already be sorted, but defensive)
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].TimestampNs < changes[j].TimestampNs
	})

	var intervals []*pb.GVLStateInterval
	var currentState pb.GVLState
	var currentStart uint64

	for i, change := range changes {
		if i == 0 {
			// First event — start the first interval
			currentState = change.State
			currentStart = change.TimestampNs
			continue
		}

		// Skip duplicate consecutive states
		if change.State == currentState {
			continue
		}

		// Close the previous interval
		intervals = append(intervals, &pb.GVLStateInterval{
			StartNs: currentStart,
			EndNs:   change.TimestampNs,
			State:   currentState,
		})

		// Start new interval
		currentState = change.State
		currentStart = change.TimestampNs
	}

	// Close the final interval. Cap its duration to avoid a misleading
	// multi-second marker when the thread goes idle. Without a cap, the
	// last interval stretches to captureEndNs — e.g., a STALLED that
	// happens once at T=1s produces a 14s marker until T=15s, even though
	// the thread is just idle waiting for a new request.
	endNs := captureEndNs
	if endNs == 0 || endNs < currentStart {
		endNs = currentStart
	}
	const maxFinalIntervalNs = 500_000_000 // 500ms — any longer is likely idle, not real GVL contention
	if endNs > currentStart+maxFinalIntervalNs {
		endNs = currentStart + maxFinalIntervalNs
	}
	if endNs > currentStart {
		intervals = append(intervals, &pb.GVLStateInterval{
			StartNs: currentStart,
			EndNs:   endNs,
			State:   currentState,
		})
	}

	return intervals
}
