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
	EventGVLWait    EventType = 6 // deprecated: use EventGVLState
	EventGVLState   EventType = 7
	EventGVLStack   EventType = 8 // Ruby stack captured at GVL SUSPENDED
	EventStackWalk  EventType = 9 // BPF stack walker raw frame event
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
// from ruby_reader.c: type(4) + pid(4) + tid(4) + weight(4) + timestamp(8) + thread_id(8) + stack_data_len(4) + native_stack_len(4) = 40
const rubySampleHeaderSize = 40

// maxRubyStackSize matches MAX_STACK_SIZE in ruby_reader.c.
// Native stack IPs are stored at a fixed offset (header + maxRubyStackSize)
// to avoid BPF verifier issues with dynamic offsets.
const maxRubyStackSize = 16384

// RubySampleEvent represents a Ruby stack sample captured by the BPF program.
// The stack data is serialized in format v2 (inline strings) by the gem.
// Native stack IPs are captured by bpf_get_stack() for C extension profiling.
type RubySampleEvent struct {
	EventHeader
	Weight         uint32 // number of sample ticks this event represents
	ThreadID       uint64
	StackDataLen   uint32
	NativeStackLen uint32   // bytes of native IPs (0 if not captured)
	StackData      []byte   // inline format v2 stack data
	NativeStackIPs []uint64 // user-space instruction pointers from bpf_get_stack
}

// RubyAllocEvent represents a sampled allocation captured by the BPF program.
// Uses the same wire format as RubySampleEvent but with additional alloc metadata
// at a fixed offset after the native stack area.
type RubyAllocEvent struct {
	RubySampleEvent        // embedded sample data (stack, native IPs)
	ObjectType      string // class name of allocated object (e.g., "String", "Array")
	SizeBytes       uint64 // rb_obj_memsize_of() result
}

// InlineFrame represents a single frame parsed from format v2 stack data.
type InlineFrame struct {
	Label string
	Path  string
	Line  uint32
}

// RawFrame represents a single frame from format v3 stack data.
// Contains the raw VALUE pointer from rb_profile_frames (iseq or cme address)
// and the line number. The collector resolves these via /proc/pid/mem.
type RawFrame struct {
	Value uint64
	Line  int32
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
	// Native user-space stack at syscall time (from bpf_get_stack)
	NativeStackIPs []uint64
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
	PrevState uint8 // task state when going off-CPU (0=RUNNING, 1=INTERRUPTIBLE, 2=UNINTERRUPTIBLE)
	PrevPID   uint32
	NextPID   uint32
	OffCPUNs  uint64
	RunqLatNs uint64
}

// GVLWaitEvent captures a GVL wait duration.
// Deprecated: use GVLStateChangeEvent for continuous state intervals.
// Layout: event_type(4) + pid(4) + tid(4) + pad(4) + wait_ns(8) + timestamp_ns(8) + thread_value(8) = 40 bytes
type GVLWaitEvent struct {
	EventHeader
	WaitNs      uint64 // how long the thread waited for the GVL
	TimestampNs uint64 // when the thread acquired the GVL
	ThreadValue uint64 // Ruby thread VALUE for cross-referencing
}

// GVL state constants matching the BPF-side and proto enum values.
const (
	GVLStateRunning   uint8 = 1
	GVLStateStalled   uint8 = 2
	GVLStateSuspended uint8 = 3
)

// GVLStateChangeEvent captures a raw GVL state transition from the BPF program.
// Layout: event_type(4) + pid(4) + tid(4) + gvl_state(4) + timestamp_ns(8) + thread_value(8) = 32 bytes
type GVLStateChangeEvent struct {
	EventHeader
	GVLState    uint8  // GVLStateRunning/Stalled/Suspended
	TimestampNs uint64 // CLOCK_MONOTONIC from the gem
	ThreadValue uint64 // Ruby thread VALUE
}

// GVLStackEvent carries the Ruby call stack captured at the moment a thread
// releases the GVL (SUSPENDED). Used to correlate with I/O events on the
// same TID to produce unified Ruby + native C call trees.
// Layout: event_type(4) + pid(4) + tid(4) + stack_len(4) + timestamp_ns(8) + stack_data(variable)
type GVLStackEvent struct {
	EventHeader
	TimestampNs uint64
	StackData   []byte // serialized InlineStack (format v2)
}

// ParseEvent decodes raw bytes from the BPF ring buffer into a typed event.
// It returns one of: *RubySampleEvent, *RubySpanEvent, *IOEvent, *SchedEvent.
func ParseEvent(data []byte) (any, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("event too short: %d bytes", len(data))
	}

	eventType := EventType(binary.LittleEndian.Uint32(data[0:4]))

	switch eventType {
	case EventRubySample:
		return parseRubySampleFromRaw(data)
	case EventRubyAlloc:
		return parseRubyAllocFromRaw(data)
	case EventRubySpan:
		hdr := parseHeader(data)
		return parseRubySpan(hdr, data)
	case EventIO:
		hdr := parseHeader(data)
		return parseIOEvent(hdr, data)
	case EventSched:
		hdr := parseHeader(data)
		return parseSchedEvent(hdr, data)
	case EventGVLWait:
		return parseGVLWaitEvent(data)
	case EventGVLState:
		return parseGVLStateChangeEvent(data)
	case EventGVLStack:
		return parseGVLStackEvent(data)
	case EventStackWalk:
		return parseStackWalkEvent(data)
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
	ev.NativeStackLen = binary.LittleEndian.Uint32(data[36:40])

	// Copy inline Ruby stack data following the header
	off := rubySampleHeaderSize
	sdLen := int(ev.StackDataLen)
	if off+sdLen > len(data) {
		sdLen = len(data) - off
	}
	if sdLen > 0 {
		ev.StackData = make([]byte, sdLen)
		copy(ev.StackData, data[off:off+sdLen])
	}

	// Parse native stack IPs (fixed offset at header + MAX_STACK_SIZE = 40 + 16384 = 16424)
	nsLen := int(ev.NativeStackLen)
	if nsLen > 0 {
		nativeOff := rubySampleHeaderSize + maxRubyStackSize
		if nativeOff+nsLen <= len(data) {
			numIPs := nsLen / 8
			ev.NativeStackIPs = make([]uint64, numIPs)
			for i := 0; i < numIPs; i++ {
				ev.NativeStackIPs[i] = binary.LittleEndian.Uint64(data[nativeOff+i*8 : nativeOff+i*8+8])
			}
		}
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

// ParseRawFrameStack parses format v3 raw frame stack data.
// Format: [u8: version=3][u16: num_frames][per frame: u64 value + i32 line]
// Returns nil if data is not format v3.
func ParseRawFrameStack(data []byte) []RawFrame {
	if len(data) < 3 || data[0] != 3 {
		return nil
	}
	numFrames := int(binary.LittleEndian.Uint16(data[1:3]))
	off := 3

	frames := make([]RawFrame, 0, numFrames)
	for i := 0; i < numFrames && off+12 <= len(data); i++ {
		val := binary.LittleEndian.Uint64(data[off:])
		line := int32(binary.LittleEndian.Uint32(data[off+8:]))
		off += 12
		frames = append(frames, RawFrame{Value: val, Line: line})
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

// ioEventEnrichedSize is the minimum size of the enriched rbscope_io_event
// from io_tracer.c: header(24) + io(24) + socket(16) + tcp(48) + stack_hdr(8) = 120 bytes
// The full event with 16 stack IPs is 120 + 16*8 = 248 bytes.
const ioEventEnrichedSize = 120

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

	// Native stack IPs from bpf_get_stack (offset 112)
	// Layout: stack_len(4) + pad(4) + stack[16×8]
	if len(data) >= 120 { // at least stack_len + pad
		stackLen := binary.LittleEndian.Uint32(data[112:116])
		// skip pad at 116:120
		if stackLen > 0 && stackLen <= 16 && len(data) >= 120+int(stackLen)*8 {
			ev.NativeStackIPs = make([]uint64, stackLen)
			for i := uint32(0); i < stackLen; i++ {
				off := 120 + i*8
				ev.NativeStackIPs[i] = binary.LittleEndian.Uint64(data[off : off+8])
			}
		}
	}

	return ev, nil
}

func parseSchedEvent(_ EventHeader, data []byte) (*SchedEvent, error) {
	// BPF struct layout (32 bytes):
	//   event_type(4) + pid(4) + tid(4) + prev_state(1) + pad(3) +
	//   off_cpu_ns(8) + timestamp_ns(8)
	const schedSize = 32
	if len(data) < schedSize {
		return nil, fmt.Errorf("sched event too short: %d bytes", len(data))
	}
	ev := &SchedEvent{}
	ev.Type = EventSched
	ev.PID = binary.LittleEndian.Uint32(data[4:8])
	ev.TID = binary.LittleEndian.Uint32(data[8:12])
	ev.PrevState = data[12]
	ev.OffCPUNs = binary.LittleEndian.Uint64(data[16:24])
	ev.Timestamp = binary.LittleEndian.Uint64(data[24:32])
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

// parseGVLWaitEvent parses a GVL wait event from the BPF ring buffer.
// Layout: event_type(4) + pid(4) + tid(4) + pad(4) + wait_ns(8) + timestamp_ns(8) + thread_value(8) = 40 bytes
// allocMetaOffset is the fixed byte offset in the BPF scratch buffer where
// alloc metadata (type name + size) is written. Matches ALLOC_META_OFF in ruby_reader.c.
const allocMetaOffset = rubySampleHeaderSize + maxRubyStackSize + maxNativeStackSize

// maxNativeStackSize matches MAX_NATIVE_STACK_SIZE in ruby_reader.c (64 IPs × 8 bytes).
const maxNativeStackSize = 512

// parseRubyAllocFromRaw parses a ruby alloc event with additional metadata.
// Wire format:
//
//	[0..40)   ruby_sample_event header (event_type=3)
//	[40..40+maxRubyStackSize)   Ruby stack data
//	[40+maxRubyStackSize..allocMetaOffset)   Native IPs
//	[allocMetaOffset..)   Alloc metadata: type_len(4) + alloc_size(8) + type_name(type_len)
func parseRubyAllocFromRaw(data []byte) (*RubyAllocEvent, error) {
	sample, err := parseRubySampleFromRaw(data)
	if err != nil {
		return nil, err
	}

	ev := &RubyAllocEvent{RubySampleEvent: *sample}

	// Parse alloc metadata if present
	if len(data) > allocMetaOffset+12 {
		typeLen := binary.LittleEndian.Uint32(data[allocMetaOffset : allocMetaOffset+4])
		ev.SizeBytes = binary.LittleEndian.Uint64(data[allocMetaOffset+4 : allocMetaOffset+12])

		if typeLen > 0 && typeLen <= 256 && allocMetaOffset+12+int(typeLen) <= len(data) {
			ev.ObjectType = string(data[allocMetaOffset+12 : allocMetaOffset+12+int(typeLen)])
		}
	}

	return ev, nil
}

// parseGVLWaitEvent parses a GVL wait event from the BPF ring buffer.
// Layout: event_type(4) + pid(4) + tid(4) + pad(4) + wait_ns(8) + timestamp_ns(8) + thread_value(8) = 40 bytes
func parseGVLWaitEvent(data []byte) (*GVLWaitEvent, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("GVL event too short: %d bytes (need 40)", len(data))
	}
	return &GVLWaitEvent{
		EventHeader: EventHeader{
			Type: EventGVLWait,
			PID:  binary.LittleEndian.Uint32(data[4:8]),
			TID:  binary.LittleEndian.Uint32(data[8:12]),
		},
		WaitNs:      binary.LittleEndian.Uint64(data[16:24]),
		TimestampNs: binary.LittleEndian.Uint64(data[24:32]),
		ThreadValue: binary.LittleEndian.Uint64(data[32:40]),
	}, nil
}

// parseGVLStateChangeEvent parses a GVL state change event from the BPF ring buffer.
// Layout: event_type(4) + pid(4) + tid(4) + gvl_state(4) + timestamp_ns(8) + thread_value(8) = 32 bytes
func parseGVLStateChangeEvent(data []byte) (*GVLStateChangeEvent, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("GVL state event too short: %d bytes (need 32)", len(data))
	}
	return &GVLStateChangeEvent{
		EventHeader: EventHeader{
			Type: EventGVLState,
			PID:  binary.LittleEndian.Uint32(data[4:8]),
			TID:  binary.LittleEndian.Uint32(data[8:12]),
		},
		GVLState:    uint8(binary.LittleEndian.Uint32(data[12:16])), // #nosec G115 -- wire format, state fits in uint8
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		ThreadValue: binary.LittleEndian.Uint64(data[24:32]),
	}, nil
}

// parseGVLStackEvent parses a GVL stack event from the BPF ring buffer.
// Layout: event_type(4) + pid(4) + tid(4) + stack_len(4) + timestamp_ns(8) + stack_data(variable)
func parseGVLStackEvent(data []byte) (*GVLStackEvent, error) {
	const headerSize = 24 // 4+4+4+4+8
	if len(data) < headerSize {
		return nil, fmt.Errorf("GVL stack event too short: %d bytes (need %d)", len(data), headerSize)
	}
	stackLen := binary.LittleEndian.Uint32(data[12:16])
	if int(stackLen) > len(data)-headerSize {
		return nil, fmt.Errorf("GVL stack event stack_len %d exceeds data %d", stackLen, len(data)-headerSize)
	}
	stackData := make([]byte, stackLen)
	copy(stackData, data[headerSize:headerSize+int(stackLen)])
	return &GVLStackEvent{
		EventHeader: EventHeader{
			Type: EventGVLStack,
			PID:  binary.LittleEndian.Uint32(data[4:8]),
			TID:  binary.LittleEndian.Uint32(data[8:12]),
		},
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		StackData:   stackData,
	}, nil
}

// StackWalkFrame represents a single frame from the BPF stack walker.
type StackWalkFrame struct {
	IseqAddr uint64 // pointer to rb_iseq_struct (0 = cfunc)
	PC       uint64 // program counter within iseq
	SelfVal  uint64 // cfp->self (receiver VALUE, for class name resolution)
	IsCfunc  bool
}

// StackWalkEvent is the raw event from the BPF stack walker.
// Contains iseq addresses that need to be resolved to method names
// by the frame resolver (via /proc/pid/mem reads).
type StackWalkEvent struct {
	EventHeader
	NumFrames      uint32
	ThreadID       uint64
	NativeStackLen uint32
	Frames         []StackWalkFrame
	NativeStackIPs []uint64
}

// stackWalkHeaderSize: event_type(4)+pid(4)+tid(4)+num_frames(4)+timestamp(8)+thread_id(8)+native_stack_len(4)+pad(4) = 40
const stackWalkHeaderSize = 40

// stackWalkFrameSize: iseq_addr(8)+pc(8)+self_val(8)+is_cfunc(4)+pad(4) = 32
const stackWalkFrameSize = 32

func parseStackWalkEvent(data []byte) (*StackWalkEvent, error) {
	if len(data) < stackWalkHeaderSize {
		return nil, fmt.Errorf("stack walk event too short: %d bytes", len(data))
	}

	ev := &StackWalkEvent{}
	ev.Type = EventStackWalk
	ev.PID = binary.LittleEndian.Uint32(data[4:8])
	ev.TID = binary.LittleEndian.Uint32(data[8:12])
	ev.NumFrames = binary.LittleEndian.Uint32(data[12:16])
	ev.Timestamp = binary.LittleEndian.Uint64(data[16:24])
	ev.ThreadID = binary.LittleEndian.Uint64(data[24:32])
	ev.NativeStackLen = binary.LittleEndian.Uint32(data[32:36])

	// Parse Ruby frames
	frameStart := stackWalkHeaderSize
	for i := uint32(0); i < ev.NumFrames; i++ {
		off := frameStart + int(i)*stackWalkFrameSize
		if off+stackWalkFrameSize > len(data) {
			break
		}
		frame := StackWalkFrame{
			IseqAddr: binary.LittleEndian.Uint64(data[off : off+8]),
			PC:       binary.LittleEndian.Uint64(data[off+8 : off+16]),
			SelfVal:  binary.LittleEndian.Uint64(data[off+16 : off+24]),
			IsCfunc:  binary.LittleEndian.Uint32(data[off+24:off+28]) == 1,
		}
		ev.Frames = append(ev.Frames, frame)
	}

	// Trim trailing garbage frames past the valid stack bottom.
	// The BPF walker can overshoot end_cfp by a few slots, producing
	// frames with bogus iseq pointers (small values, instruction bytes).
	// Walk backward from the end and drop frames whose iseq address
	// is clearly not a valid heap pointer (< 0x1000 or not 8-byte aligned).
	for len(ev.Frames) > 0 {
		last := ev.Frames[len(ev.Frames)-1]
		if last.IsCfunc {
			// cfunc with iseq==0 is valid; but check if PC (ep) is sane
			if last.PC < 0x1000 {
				ev.Frames = ev.Frames[:len(ev.Frames)-1]
				continue
			}
			break
		}
		if last.IseqAddr < 0x10000 || last.IseqAddr&0x7 != 0 {
			ev.Frames = ev.Frames[:len(ev.Frames)-1]
			continue
		}
		break
	}

	// Parse native stack IPs
	// Native stack is at a fixed offset in the struct: after all MAX_RUBY_FRAMES frames
	// MAX_RUBY_FRAMES = 768, each 32 bytes = 24576 bytes of frame data
	nativeStart := stackWalkHeaderSize + 768*stackWalkFrameSize
	nativeBytes := int(ev.NativeStackLen)
	if nativeStart+nativeBytes <= len(data) && nativeBytes > 0 {
		numIPs := nativeBytes / 8
		for i := 0; i < numIPs; i++ {
			off := nativeStart + i*8
			ip := binary.LittleEndian.Uint64(data[off : off+8])
			if ip != 0 {
				ev.NativeStackIPs = append(ev.NativeStackIPs, ip)
			}
		}
	}

	return ev, nil
}
