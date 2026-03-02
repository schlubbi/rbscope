package collector

import (
	"encoding/binary"
	"fmt"
)

// EventType constants matching the BPF-side enum.
const (
	EventRubySample EventType = 1
	EventRubySpan   EventType = 2
	EventRubyAlloc  EventType = 3
	EventIO         EventType = 4
	EventSched      EventType = 5
)

// EventType identifies the kind of event produced by the BPF programs.
type EventType uint32

// eventHeaderSize is the fixed-size prefix shared by every event.
const eventHeaderSize = 24 // type(4) + pid(4) + tid(4) + timestamp(8) + cpu(4)

// EventHeader is the common prefix for all BPF ring-buffer events.
type EventHeader struct {
	Type      EventType
	PID       uint32
	TID       uint32
	Timestamp uint64
	CPU       uint32
}

// RubySampleEvent represents a Ruby stack sample captured by the BPF program.
type RubySampleEvent struct {
	EventHeader
	StackID   uint32
	StackLen  uint32
	TraceID   [16]byte
	SpanID    [8]byte
	ThreadID  uint64
	Frames    [128]uint64 // instruction pointers
}

// RubySpanEvent marks a span transition (enter/exit) observed in the Ruby VM.
type RubySpanEvent struct {
	EventHeader
	TraceID  [16]byte
	SpanID   [8]byte
	ParentID [8]byte
	Enter    uint8 // 1 = enter, 0 = exit
	_        [7]byte
}

// IOEvent captures a blocking I/O operation (file, socket, pipe).
type IOEvent struct {
	EventHeader
	FD        int32
	Op        uint32 // 1=read, 2=write, 3=sendmsg, 4=recvmsg
	Bytes     uint64
	LatencyNs uint64
}

// SchedEvent captures a context-switch or scheduling event.
type SchedEvent struct {
	EventHeader
	PrevPID   uint32
	NextPID   uint32
	OffCPUNs  uint64
	RunqLatNs uint64
}

// ParseEvent decodes raw bytes from the BPF ring buffer into a typed event.
// It returns one of: *RubySampleEvent, *RubySpanEvent, *IOEvent, *SchedEvent.
func ParseEvent(data []byte) (any, error) {
	if len(data) < eventHeaderSize {
		return nil, fmt.Errorf("event too short: %d bytes", len(data))
	}

	hdr := parseHeader(data)

	switch hdr.Type {
	case EventRubySample:
		return parseRubySample(hdr, data)
	case EventRubySpan:
		return parseRubySpan(hdr, data)
	case EventRubyAlloc:
		// Alloc events share the sample layout for now.
		return parseRubySample(hdr, data)
	case EventIO:
		return parseIOEvent(hdr, data)
	case EventSched:
		return parseSchedEvent(hdr, data)
	default:
		return nil, fmt.Errorf("unknown event type: %d", hdr.Type)
	}
}

func parseHeader(data []byte) EventHeader {
	return EventHeader{
		Type:      EventType(binary.LittleEndian.Uint32(data[0:4])),
		PID:       binary.LittleEndian.Uint32(data[4:8]),
		TID:       binary.LittleEndian.Uint32(data[8:12]),
		Timestamp: binary.LittleEndian.Uint64(data[12:20]),
		CPU:       binary.LittleEndian.Uint32(data[20:24]),
	}
}

func parseRubySample(hdr EventHeader, data []byte) (*RubySampleEvent, error) {
	const minSize = eventHeaderSize + 4 + 4 + 16 + 8 + 8 // header + stackID + stackLen + traceID + spanID + threadID
	if len(data) < minSize {
		return nil, fmt.Errorf("ruby sample event too short: %d bytes", len(data))
	}
	ev := &RubySampleEvent{EventHeader: hdr}
	off := eventHeaderSize
	ev.StackID = binary.LittleEndian.Uint32(data[off:])
	off += 4
	ev.StackLen = binary.LittleEndian.Uint32(data[off:])
	off += 4
	copy(ev.TraceID[:], data[off:off+16])
	off += 16
	copy(ev.SpanID[:], data[off:off+8])
	off += 8
	ev.ThreadID = binary.LittleEndian.Uint64(data[off:])
	off += 8

	n := int(ev.StackLen)
	if n > len(ev.Frames) {
		n = len(ev.Frames)
	}
	for i := 0; i < n && off+8 <= len(data); i++ {
		ev.Frames[i] = binary.LittleEndian.Uint64(data[off:])
		off += 8
	}
	return ev, nil
}

func parseRubySpan(hdr EventHeader, data []byte) (*RubySpanEvent, error) {
	const minSize = eventHeaderSize + 16 + 8 + 8 + 1
	if len(data) < minSize {
		return nil, fmt.Errorf("ruby span event too short: %d bytes", len(data))
	}
	ev := &RubySpanEvent{EventHeader: hdr}
	off := eventHeaderSize
	copy(ev.TraceID[:], data[off:off+16])
	off += 16
	copy(ev.SpanID[:], data[off:off+8])
	off += 8
	copy(ev.ParentID[:], data[off:off+8])
	off += 8
	ev.Enter = data[off]
	return ev, nil
}

func parseIOEvent(hdr EventHeader, data []byte) (*IOEvent, error) {
	const minSize = eventHeaderSize + 4 + 4 + 8 + 8
	if len(data) < minSize {
		return nil, fmt.Errorf("io event too short: %d bytes", len(data))
	}
	ev := &IOEvent{EventHeader: hdr}
	off := eventHeaderSize
	ev.FD = int32(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	ev.Op = binary.LittleEndian.Uint32(data[off:])
	off += 4
	ev.Bytes = binary.LittleEndian.Uint64(data[off:])
	off += 8
	ev.LatencyNs = binary.LittleEndian.Uint64(data[off:])
	return ev, nil
}

func parseSchedEvent(hdr EventHeader, data []byte) (*SchedEvent, error) {
	const minSize = eventHeaderSize + 4 + 4 + 8 + 8
	if len(data) < minSize {
		return nil, fmt.Errorf("sched event too short: %d bytes", len(data))
	}
	ev := &SchedEvent{EventHeader: hdr}
	off := eventHeaderSize
	ev.PrevPID = binary.LittleEndian.Uint32(data[off:])
	off += 4
	ev.NextPID = binary.LittleEndian.Uint32(data[off:])
	off += 4
	ev.OffCPUNs = binary.LittleEndian.Uint64(data[off:])
	off += 8
	ev.RunqLatNs = binary.LittleEndian.Uint64(data[off:])
	return ev, nil
}
