package timeline

import (
	"testing"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func TestIdleClassifier_DaemonPort(t *testing.T) {
	c := NewIdleClassifier()

	// Read on port 3000 (Puma) → idle
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, LocalPort: 3000,
	})
	if state != pb.ThreadState_THREAD_STATE_IDLE {
		t.Errorf("read on port 3000: got %v, want IDLE", state)
	}
}

func TestIdleClassifier_EphemeralPort(t *testing.T) {
	c := NewIdleClassifier()

	// Read on port 54321 (ephemeral, client connection) → active waiting
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, LocalPort: 54321, RemotePort: 3306,
	})
	if state != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("read on port 54321: got %v, want OFF_CPU_IO", state)
	}
}

func TestIdleClassifier_TCPListen(t *testing.T) {
	c := NewIdleClassifier()

	// TCP LISTEN state → always idle regardless of port
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, SockState: 10, // TCP_LISTEN
		LocalPort: 54321,
	})
	if state != pb.ThreadState_THREAD_STATE_IDLE {
		t.Errorf("TCP LISTEN: got %v, want IDLE", state)
	}
}

func TestIdleClassifier_AdditionalServicePort(t *testing.T) {
	c := NewIdleClassifier()
	c.AddServicePort(18080)

	// Read on port 18080 (above threshold, but marked as service) → idle
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, LocalPort: 18080,
	})
	if state != pb.ThreadState_THREAD_STATE_IDLE {
		t.Errorf("read on additional service port 18080: got %v, want IDLE", state)
	}
}

func TestIdleClassifier_WriteNotIdle(t *testing.T) {
	c := NewIdleClassifier()

	// Write on port 3000 → active (writing a response, not idle)
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpWrite, FdType: 2, LocalPort: 3000,
	})
	if state != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("write on port 3000: got %v, want OFF_CPU_IO", state)
	}
}

func TestIdleClassifier_FileIO(t *testing.T) {
	c := NewIdleClassifier()

	// File read → active (disk I/O)
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 1,
	})
	if state != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("file read: got %v, want OFF_CPU_IO", state)
	}
}

func TestIdleClassifier_NilEvent(t *testing.T) {
	c := NewIdleClassifier()

	// nil → default to active waiting
	state := c.ClassifyIOState(nil)
	if state != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("nil: got %v, want OFF_CPU_IO", state)
	}
}

func TestIdleClassifier_ThresholdBoundary(t *testing.T) {
	c := NewIdleClassifier()
	c.DaemonPortThreshold = 10000

	// Port 10000 → idle (at threshold)
	state := c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, LocalPort: 10000,
	})
	if state != pb.ThreadState_THREAD_STATE_IDLE {
		t.Errorf("port 10000 (at threshold): got %v, want IDLE", state)
	}

	// Port 10001 → active (above threshold)
	state = c.ClassifyIOState(&collector.IOEvent{
		Op: collector.IoOpRead, FdType: 2, LocalPort: 10001,
	})
	if state != pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
		t.Errorf("port 10001 (above threshold): got %v, want OFF_CPU_IO", state)
	}
}

func TestBuilder_IdleDetection_Integration(t *testing.T) {
	b := NewBuilder("test", "host", 1000, 99)

	// Ingest an IO event on a daemon port (Puma reading on port 3000)
	b.Ingest(&collector.IOEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventIO, PID: 1000, TID: 100, Timestamp: 1000,
		},
		Op: collector.IoOpRead, FD: 5, Bytes: 0, LatencyNs: 500_000_000,
		FdType: 2, SockState: 1, LocalPort: 3000,
	})

	// Ingest a sched event that overlaps the IO event
	b.Ingest(&collector.SchedEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventSched, PID: 1000, TID: 100, Timestamp: 500_000_000,
		},
		OffCPUNs: 499_000_000,
	})

	// Ingest an IO event on an ephemeral port (MySQL query)
	b.Ingest(&collector.IOEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventIO, PID: 1000, TID: 100, Timestamp: 600_000_000,
		},
		Op: collector.IoOpRead, FD: 7, Bytes: 4096, LatencyNs: 2_000_000,
		FdType: 2, SockState: 1, LocalPort: 54321, RemotePort: 3306,
	})

	// Ingest a sched event that overlaps the MySQL IO
	b.Ingest(&collector.SchedEvent{
		EventHeader: collector.EventHeader{
			Type: collector.EventSched, PID: 1000, TID: 100, Timestamp: 602_000_000,
		},
		OffCPUNs: 1_800_000,
	})

	capture := b.Build()
	thread := capture.Threads[0]

	// Should have derived states
	if len(thread.States) == 0 {
		t.Fatal("expected thread states")
	}

	// Find the IDLE and OFF_CPU_IO states
	var foundIdle, foundActiveIO bool
	for _, s := range thread.States {
		if s.State == pb.ThreadState_THREAD_STATE_IDLE {
			foundIdle = true
		}
		if s.State == pb.ThreadState_THREAD_STATE_OFF_CPU_IO {
			foundActiveIO = true
		}
	}

	if !foundIdle {
		t.Error("expected IDLE state for daemon port read")
	}
	if !foundActiveIO {
		t.Error("expected OFF_CPU_IO state for client port read")
	}
}
