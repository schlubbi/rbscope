package timeline

import (
	"sort"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// crossRefIOToSamples sets NearestSampleIdx on each IOEvent to point at
// the closest sample by timestamp (binary search).
func crossRefIOToSamples(tb *threadBuilder) {
	if len(tb.samples) == 0 {
		return
	}
	for _, io := range tb.ioEvents {
		idx := nearestSampleIdx(tb.samples, io.TimestampNs)
		io.NearestSampleIdx = uint32(idx) // #nosec G115
	}
}

// crossRefIOToSched links IOEvents with SchedEvents that overlap in time.
// An IO event caused an off-CPU period if the IO latency window overlaps
// the sched off-CPU window.
func crossRefIOToSched(tb *threadBuilder) {
	if len(tb.ioEvents) == 0 || len(tb.schedEvents) == 0 {
		return
	}
	for ioIdx, io := range tb.ioEvents {
		ioStart := io.TimestampNs
		ioEnd := ioStart + io.LatencyNs
		for schedIdx, sched := range tb.schedEvents {
			schedEnd := sched.TimestampNs
			schedStart := schedEnd - sched.OffCpuNs
			// Check overlap: IO window intersects off-CPU window
			if ioStart <= schedEnd && ioEnd >= schedStart {
				io.CausedSchedEventIdx = uint32(schedIdx) // #nosec G115
				sched.CausedByIoIdx = uint32(ioIdx)       // #nosec G115
				sched.Reason = pb.OffCPUReason_OFF_CPU_IO_BLOCKED
				break // one IO per sched event
			}
		}
	}
}

// deriveThreadStates builds ThreadStateInterval entries from sched events.
// Gaps between off-CPU periods are assumed to be RUNNING.
func deriveThreadStates(tb *threadBuilder) []*pb.ThreadStateInterval {
	if len(tb.schedEvents) == 0 {
		return nil
	}

	var states []*pb.ThreadStateInterval
	var lastOnCPU uint64

	for i, sched := range tb.schedEvents {
		offStart := sched.TimestampNs - sched.OffCpuNs
		offEnd := sched.TimestampNs

		// Fill gap before this off-CPU period with RUNNING
		if lastOnCPU > 0 && offStart > lastOnCPU {
			states = append(states, &pb.ThreadStateInterval{
				StartNs: lastOnCPU,
				EndNs:   offStart,
				State:   pb.ThreadState_THREAD_STATE_RUNNING,
			})
		}

		// Map the off-CPU reason to a thread state
		state := offCPUReasonToState(sched.Reason)
		states = append(states, &pb.ThreadStateInterval{
			StartNs:       offStart,
			EndNs:         offEnd,
			State:         state,
			CauseEventIdx: uint32(i), // #nosec G115
		})

		lastOnCPU = offEnd
	}

	return states
}

func offCPUReasonToState(reason pb.OffCPUReason) pb.ThreadState {
	switch reason {
	case pb.OffCPUReason_OFF_CPU_IO_BLOCKED:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	case pb.OffCPUReason_OFF_CPU_GVL_WAIT:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_GVL
	case pb.OffCPUReason_OFF_CPU_MUTEX:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_MUTEX
	case pb.OffCPUReason_OFF_CPU_VOLUNTARY_SLEEP:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_SLEEP
	case pb.OffCPUReason_OFF_CPU_PREEMPTED:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED
	default:
		return pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN
	}
}

// nearestSampleIdx returns the index of the sample closest to targetNs.
func nearestSampleIdx(samples []*pb.Sample, targetNs uint64) int {
	idx := sort.Search(len(samples), func(i int) bool {
		return samples[i].TimestampNs >= targetNs
	})
	if idx == 0 {
		return 0
	}
	if idx >= len(samples) {
		return len(samples) - 1
	}
	// Check which neighbor is closer
	before := targetNs - samples[idx-1].TimestampNs
	after := samples[idx].TimestampNs - targetNs
	if before <= after {
		return idx - 1
	}
	return idx
}
