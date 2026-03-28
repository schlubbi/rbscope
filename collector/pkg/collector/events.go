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

// rubySampleHeaderSize is the header size for the updated ruby_sample event
// from ruby_reader.c: type(4) + pid(4) + tid(4) + pad(4) + timestamp(8) + thread_id(8) + stack_data_len(4) + pad(4) = 40
const rubySampleHeaderSize = 40

// RubySampleEvent represents a Ruby stack sample captured by the BPF program.
// The stack data is serialized in format v2 (inline strings) by the gem.
type RubySampleEvent struct {
	EventHeader
	Weight       uint32 // number of sample ticks this event represents
	ThreadID     uint64
	StackDataLen uint32
	StackData    []byte // inline format v2 stack data
}

// InlineFrame represents a single frame parsed from format v2 stack data.
type InlineFrame struct {
	Label string
	Path  string
	Line  uint32
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
	if len(data) < 4 {
		return nil, fmt.Errorf("event too short: %d bytes", len(data))
	}

	eventType := EventType(binary.LittleEndian.Uint32(data[0:4]))

	switch eventType {
	case EventRubySample, EventRubyAlloc:
		// Ruby sample events use the new 40-byte header layout
		return parseRubySampleFromRaw(data)
	case EventRubySpan:
		hdr := parseHeader(data)
		return parseRubySpan(hdr, data)
	case EventIO:
		hdr := parseHeader(data)
		return parseIOEvent(hdr, data)
	case EventSched:
		hdr := parseHeader(data)
		return parseSchedEvent(hdr, data)
	default:
		return nil, fmt.Errorf("unknown event type: %d", eventType)
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

// parseRubySampleFromRaw parses the complete ruby_sample_event from raw BPF bytes.
// Layout: event_type(4) + pid(4) + tid(4) + weight(4) + timestamp_ns(8) + thread_id(8) + stack_data_len(4) + _pad1(4) = 40 bytes header
// Followed by stack_data_len bytes of inline format v2 stack data.
func parseRubySampleFromRaw(data []byte) (*RubySampleEvent, error) {
	if len(data) < rubySampleHeaderSize {
		return nil, fmt.Errorf("ruby sample event too short: %d bytes", len(data))
	}
	ev := &RubySampleEvent{}
	ev.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	ev.PID = binary.LittleEndian.Uint32(data[4:8])
	ev.TID = binary.LittleEndian.Uint32(data[8:12])
	ev.Weight = binary.LittleEndian.Uint32(data[12:16])
	if ev.Weight == 0 {
		ev.Weight = 1 // pre-weight events default to 1
	}
	ev.Timestamp = binary.LittleEndian.Uint64(data[16:24])
	ev.ThreadID = binary.LittleEndian.Uint64(data[24:32])
	ev.StackDataLen = binary.LittleEndian.Uint32(data[32:36])
	// skip _pad1 at 36:40

	// Copy inline stack data following the header
	off := rubySampleHeaderSize
	sdLen := int(ev.StackDataLen)
	if off+sdLen > len(data) {
		sdLen = len(data) - off
	}
	if sdLen > 0 {
		ev.StackData = make([]byte, sdLen)
		copy(ev.StackData, data[off:off+sdLen])
	}
	return ev, nil
}

// ParseInlineStack parses format v2 inline string stack data into frames.
// Returns nil on empty or invalid data.
func ParseInlineStack(data []byte) []InlineFrame {
	if len(data) < 3 {
		return nil
	}
	version := data[0]
	if version != 2 {
		return nil
	}
	numFrames := int(binary.LittleEndian.Uint16(data[1:3]))
	off := 3

	frames := make([]InlineFrame, 0, numFrames)
	for i := 0; i < numFrames && off < len(data); i++ {
		// label
		if off+2 > len(data) {
			break
		}
		labelLen := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if off+labelLen > len(data) {
			break
		}
		label := string(data[off : off+labelLen])
		off += labelLen

		// path
		if off+2 > len(data) {
			break
		}
		pathLen := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if off+pathLen > len(data) {
			break
		}
		path := string(data[off : off+pathLen])
		off += pathLen

		// line
		if off+4 > len(data) {
			break
		}
		line := binary.LittleEndian.Uint32(data[off:])
		off += 4

		frames = append(frames, InlineFrame{Label: label, Path: path, Line: line})
	}
	return frames
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
	ev.FD = int32(binary.LittleEndian.Uint32(data[off:])) // #nosec G115 -- wire format
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
