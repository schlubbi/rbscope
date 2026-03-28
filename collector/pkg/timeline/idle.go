package timeline

import (
	"github.com/schlubbi/rbscope/collector/pkg/collector"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// DefaultDaemonPortThreshold is the maximum port number considered a
// "service port." Threads doing read-class I/O on a local port at or
// below this threshold are classified as idle (waiting for work).
// Ephemeral/client ports (typically 32768-65535) indicate active waiting
// on a downstream response.
const DefaultDaemonPortThreshold = 10000

// IdleClassifier determines whether an I/O-blocked thread is idle
// (waiting for the next request) or actively waiting (blocked on a
// downstream response). Inspired by 0xtools/xCapture's daemon-port
// heuristic.
type IdleClassifier struct {
	// DaemonPortThreshold: local ports ≤ this are "service ports."
	// A thread reading from a service port is idle.
	DaemonPortThreshold uint16

	// AdditionalServicePorts: extra ports to treat as service ports
	// even if above the threshold (e.g. 8080, 9292).
	AdditionalServicePorts map[uint16]bool
}

// NewIdleClassifier creates a classifier with the default threshold.
func NewIdleClassifier() *IdleClassifier {
	return &IdleClassifier{
		DaemonPortThreshold:    DefaultDaemonPortThreshold,
		AdditionalServicePorts: make(map[uint16]bool),
	}
}

// AddServicePort marks a port as a service port regardless of threshold.
func (c *IdleClassifier) AddServicePort(port uint16) {
	c.AdditionalServicePorts[port] = true
}

// isServicePort returns true if the port is a daemon/service port.
func (c *IdleClassifier) isServicePort(port uint16) bool {
	if port == 0 {
		return false
	}
	if port <= c.DaemonPortThreshold {
		return true
	}
	return c.AdditionalServicePorts[port]
}

// ClassifyIOState determines the thread state for an I/O-blocked period.
// Returns THREAD_STATE_IDLE for daemon threads waiting for work, or the
// original IO-blocked state for active waiting.
func (c *IdleClassifier) ClassifyIOState(ioEv *collector.IOEvent) pb.ThreadState {
	if ioEv == nil {
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	}

	// TCP LISTEN state → always idle (accept loop)
	if ioEv.FdType == 2 && ioEv.SockState == 10 { // FD_TYPE_TCP, TCP_LISTEN
		return pb.ThreadState_THREAD_STATE_IDLE
	}

	// Read-class operations on a service port → idle
	if isReadOp(ioEv.Op) && ioEv.FdType == 2 { // TCP socket
		if c.isServicePort(ioEv.LocalPort) {
			return pb.ThreadState_THREAD_STATE_IDLE
		}
		// Client/ephemeral port → active waiting on downstream
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	}

	// Unix sockets → active waiting (IPC in progress)
	if ioEv.FdType == 4 { // FD_TYPE_UNIX
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	}

	// Pipe reads → active waiting (inter-process communication)
	if ioEv.FdType == 5 && isReadOp(ioEv.Op) { // FD_TYPE_PIPE
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	}

	// File I/O → active waiting
	if ioEv.FdType == 1 { // FD_TYPE_FILE
		return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
	}

	return pb.ThreadState_THREAD_STATE_OFF_CPU_IO
}

// isReadOp returns true for read-class I/O operations.
func isReadOp(op uint32) bool {
	return op == collector.IoOpRead || op == collector.IoOpRecvfrom
}
