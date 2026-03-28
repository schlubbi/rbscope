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
	Op        uint32 // 1=read, 2=write, 3=sendto, 4=recvfrom, 5=connect
	Bytes     int64
	LatencyNs uint64
	// Socket enrichment (from BPF FD resolution)
	FdType     uint8  // 0=unknown, 1=file, 2=tcp, 3=udp, 4=unix, 5=pipe
	SockState  uint8  // TCP state
	LocalPort  uint16 // host byte order
	RemotePort uint16 // host byte order
	LocalAddr  uint32 // IPv4, network byte order
	RemoteAddr uint32 // IPv4, network byte order
	// TCP performance stats
	TCPStats *IOTCPStats // nil if not a TCP socket
}

// IOTCPStats holds TCP performance metrics captured from struct tcp_sock.
type IOTCPStats struct {
	SrttUs        uint32
	SndCwnd       uint32
	TotalRetrans  uint32
	PacketsOut    uint32
	RetransOut    uint32
	LostOut       uint32
	RcvWnd        uint32
	BytesSent     uint64
	BytesReceived uint64
}

// IoOp constants matching the BPF-side IO_OP_* enum.
const (
	IoOpRead     = 1
	IoOpWrite    = 2
	IoOpSendto   = 3
	IoOpRecvfrom = 4
	IoOpConnect  = 5
)

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

// ioEventEnrichedSize is the total size of the enriched rbscope_io_event
// from io_tracer.c: header(24) + io(24) + socket(16) + tcp(48) = 112 bytes
const ioEventEnrichedSize = 112

func parseIOEvent(hdr EventHeader, data []byte) (*IOEvent, error) {
	// Enriched format from io_tracer.c: 104 bytes total
	if len(data) >= ioEventEnrichedSize {
		return parseIOEventEnriched(data)
	}

	// Legacy/minimal format: just the header + basic IO fields
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
	ev.Bytes = int64(binary.LittleEndian.Uint64(data[off:])) // #nosec G115 -- wire format
	off += 8
	ev.LatencyNs = binary.LittleEndian.Uint64(data[off:])
	return ev, nil
}

// parseIOEventEnriched parses the full enriched IO event from io_tracer.c.
// Layout: header(24) + op(4) + fd(4) + bytes(8) + latency(8) +
// fd_type(1) + sock_state(1) + local_port(2) + remote_port(2) + pad(2) +
// local_addr(4) + remote_addr(4) +
// srtt(4) + cwnd(4) + retrans(4) + pkts_out(4) + retrans_out(4) + lost(4) + rcv_wnd(4) + pad(4) +
// bytes_sent(8) + bytes_received(8) = 104
func parseIOEventEnriched(data []byte) (*IOEvent, error) {
	ev := &IOEvent{}

	// Header: type(4) + pid(4) + tid(4) + pad(4) + timestamp(8) = 24
	ev.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	ev.PID = binary.LittleEndian.Uint32(data[4:8])
	ev.TID = binary.LittleEndian.Uint32(data[8:12])
	// skip pad at 12:16
	ev.Timestamp = binary.LittleEndian.Uint64(data[16:24])

	// IO fields
	ev.Op = binary.LittleEndian.Uint32(data[24:28])
	ev.FD = int32(binary.LittleEndian.Uint32(data[28:32]))    // #nosec G115 -- wire format
	ev.Bytes = int64(binary.LittleEndian.Uint64(data[32:40])) // #nosec G115 -- wire format
	ev.LatencyNs = binary.LittleEndian.Uint64(data[40:48])

	// Socket enrichment
	ev.FdType = data[48]
	ev.SockState = data[49]
	ev.LocalPort = binary.LittleEndian.Uint16(data[50:52])
	ev.RemotePort = binary.LittleEndian.Uint16(data[52:54])
	// skip pad at 54:56
	ev.LocalAddr = binary.LittleEndian.Uint32(data[56:60])
	ev.RemoteAddr = binary.LittleEndian.Uint32(data[60:64])

	// TCP stats (only populate if it's a TCP socket)
	if ev.FdType == 2 { // FD_TYPE_TCP
		tcp := &IOTCPStats{
			SrttUs:       binary.LittleEndian.Uint32(data[64:68]),
			SndCwnd:      binary.LittleEndian.Uint32(data[68:72]),
			TotalRetrans: binary.LittleEndian.Uint32(data[72:76]),
			PacketsOut:   binary.LittleEndian.Uint32(data[76:80]),
			RetransOut:   binary.LittleEndian.Uint32(data[80:84]),
			LostOut:      binary.LittleEndian.Uint32(data[84:88]),
			RcvWnd:       binary.LittleEndian.Uint32(data[88:92]),
			// skip pad at 92:96
			BytesSent:     binary.LittleEndian.Uint64(data[96:104]),
			BytesReceived: binary.LittleEndian.Uint64(data[104:112]),
		}
		// Only set if there's actual data (srtt_us > 0 indicates real stats)
		if tcp.SrttUs > 0 || tcp.TotalRetrans > 0 || tcp.PacketsOut > 0 {
			ev.TCPStats = tcp
		}
	}

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

// FormatFdInfo returns a human-readable connection string for an IOEvent.
// Examples: "tcp:10.0.0.1:3306→192.168.1.1:54321", "udp:0.0.0.0:53", "file", "unix"
func (ev *IOEvent) FormatFdInfo() string {
	switch ev.FdType {
	case 1: // FD_TYPE_FILE
		return "file"
	case 2: // FD_TYPE_TCP
		return fmt.Sprintf("tcp:%s:%d→%s:%d",
			formatIPv4(ev.LocalAddr), ev.LocalPort,
			formatIPv4(ev.RemoteAddr), ev.RemotePort)
	case 3: // FD_TYPE_UDP
		return fmt.Sprintf("udp:%s:%d→%s:%d",
			formatIPv4(ev.LocalAddr), ev.LocalPort,
			formatIPv4(ev.RemoteAddr), ev.RemotePort)
	case 4: // FD_TYPE_UNIX
		return "unix"
	case 5: // FD_TYPE_PIPE
		return "pipe"
	default:
		return ""
	}
}

// IoOpName returns the syscall name for an IO operation type.
func IoOpName(op uint32) string {
	switch op {
	case IoOpRead:
		return "read"
	case IoOpWrite:
		return "write"
	case IoOpSendto:
		return "sendto"
	case IoOpRecvfrom:
		return "recvfrom"
	case IoOpConnect:
		return "connect"
	default:
		return fmt.Sprintf("syscall_%d", op)
	}
}

// formatIPv4 converts a uint32 IPv4 address (network byte order) to a.b.c.d string.
func formatIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff)
}
