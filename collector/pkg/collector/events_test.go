package collector

import (
	"encoding/binary"
	"testing"
)

func TestParseEvent_RubySample(t *testing.T) {
	// BPF layout: type(4) + pid(4) + tid(4) + weight(4) + timestamp_ns(8) +
	// thread_id(8) + stack_data_len(4) + _pad1(4) = 40 bytes header
	// Plus inline stack data follows
	stackData := buildTestStackData("Object#foo", "/app/test.rb", 42)
	totalSize := rubySampleHeaderSize + len(stackData)
	data := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(data[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(data[4:8], 1234)
	binary.LittleEndian.PutUint32(data[8:12], 5678)
	binary.LittleEndian.PutUint32(data[12:16], 5) // weight = 5
	binary.LittleEndian.PutUint64(data[16:24], 1000000000)
	binary.LittleEndian.PutUint64(data[24:32], 99) // thread_id
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(stackData)))
	copy(data[rubySampleHeaderSize:], stackData)

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	sample, ok := evt.(*RubySampleEvent)
	if !ok {
		t.Fatalf("expected *RubySampleEvent, got %T", evt)
	}

	if sample.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", sample.PID)
	}
	if sample.TID != 5678 {
		t.Errorf("TID: got %d, want 5678", sample.TID)
	}
	if sample.Weight != 5 {
		t.Errorf("Weight: got %d, want 5", sample.Weight)
	}
	if sample.ThreadID != 99 {
		t.Errorf("ThreadID: got %d, want 99", sample.ThreadID)
	}
	if sample.StackDataLen != uint32(len(stackData)) {
		t.Errorf("StackDataLen: got %d, want %d", sample.StackDataLen, len(stackData))
	}

	frames := ParseInlineStack(sample.StackData)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Label != "Object#foo" {
		t.Errorf("frame label: got %q, want %q", frames[0].Label, "Object#foo")
	}
	if frames[0].Path != "/app/test.rb" {
		t.Errorf("frame path: got %q, want %q", frames[0].Path, "/app/test.rb")
	}
	if frames[0].Line != 42 {
		t.Errorf("frame line: got %d, want 42", frames[0].Line)
	}
}

func TestParseInlineStack_MultipleFrames(t *testing.T) {
	var buf []byte
	buf = append(buf, 2) // version
	buf = binary.LittleEndian.AppendUint16(buf, 3)

	for _, f := range []struct {
		label, path string
		line        uint32
	}{
		{"Object#foo", "/app/foo.rb", 10},
		{"Bar#baz", "/app/bar.rb", 20},
		{"<main>", "/app/main.rb", 1},
	} {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(f.label)))
		buf = append(buf, f.label...)
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(f.path)))
		buf = append(buf, f.path...)
		buf = binary.LittleEndian.AppendUint32(buf, f.line)
	}

	frames := ParseInlineStack(buf)
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	if frames[0].Label != "Object#foo" {
		t.Errorf("frame 0 label: got %q", frames[0].Label)
	}
	if frames[2].Label != "<main>" {
		t.Errorf("frame 2 label: got %q", frames[2].Label)
	}
}

func TestParseInlineStack_InvalidVersion(t *testing.T) {
	data := []byte{1, 0x01, 0x00}
	frames := ParseInlineStack(data)
	if frames != nil {
		t.Errorf("expected nil for wrong version, got %d frames", len(frames))
	}
}

func TestParseInlineStack_Empty(t *testing.T) {
	if frames := ParseInlineStack(nil); frames != nil {
		t.Error("expected nil for nil input")
	}
	if frames := ParseInlineStack([]byte{}); frames != nil {
		t.Error("expected nil for empty input")
	}
}

func TestParseEvent_IO(t *testing.T) {
	// Header(24) + fd(4) + op(4) + bytes(8) + latency(8) = 48
	data := make([]byte, 48)
	data[0] = byte(EventIO)
	data[4] = 100 // pid

	data[24] = 5 // fd
	data[28] = 1 // op = read
	data[32] = 0x00
	data[33] = 0x10 // bytes = 4096

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	ioEvt, ok := evt.(*IOEvent)
	if !ok {
		t.Fatalf("expected *IOEvent, got %T", evt)
	}

	if ioEvt.PID != 100 {
		t.Errorf("PID: got %d, want 100", ioEvt.PID)
	}
	if ioEvt.FD != 5 {
		t.Errorf("FD: got %d, want 5", ioEvt.FD)
	}
	if ioEvt.Bytes != 4096 {
		t.Errorf("Bytes: got %d, want 4096", ioEvt.Bytes)
	}
}

func TestParseEvent_TooShort(t *testing.T) {
	data := []byte{byte(EventRubySample)} // way too short
	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestParseEvent_UnknownType(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 99
	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for unknown event type")
	}
}

func TestParseEvent_Sched(t *testing.T) {
	data := make([]byte, 48)
	data[0] = byte(EventSched)
	data[24] = 200  // prevPID
	data[28] = 0x2C // nextPID = 300
	data[29] = 0x01

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	sched, ok := evt.(*SchedEvent)
	if !ok {
		t.Fatalf("expected *SchedEvent, got %T", evt)
	}
	if sched.PrevPID != 200 {
		t.Errorf("PrevPID: got %d, want 200", sched.PrevPID)
	}
	if sched.NextPID != 300 {
		t.Errorf("NextPID: got %d, want 300", sched.NextPID)
	}
}

// buildTestStackData creates a single-frame format v2 inline stack for testing.
func buildTestStackData(label, path string, line uint32) []byte {
	var buf []byte
	buf = append(buf, 2) // version = 2
	buf = binary.LittleEndian.AppendUint16(buf, 1)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(label)))
	buf = append(buf, label...)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(path)))
	buf = append(buf, path...)
	buf = binary.LittleEndian.AppendUint32(buf, line)
	return buf
}

func TestParseEvent_RubySampleWeightZeroDefaultsToOne(t *testing.T) {
	// Pre-weight events have 0 in the weight field (was _pad0).
	// Parser should default to weight=1.
	stackData := buildTestStackData("Object#bar", "/app/bar.rb", 10)
	totalSize := rubySampleHeaderSize + len(stackData)
	data := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(data[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(data[4:8], 100)
	binary.LittleEndian.PutUint32(data[8:12], 200)
	// weight at 12:16 left as 0
	binary.LittleEndian.PutUint64(data[16:24], 999)
	binary.LittleEndian.PutUint64(data[24:32], 42)
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(stackData)))
	copy(data[rubySampleHeaderSize:], stackData)

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	sample := evt.(*RubySampleEvent)
	if sample.Weight != 1 {
		t.Errorf("Weight: got %d, want 1 (default for zero)", sample.Weight)
	}
}

func TestParseEvent_IOEnriched(t *testing.T) {
	// Enriched IO event from io_tracer.c: 112 bytes
	data := make([]byte, ioEventEnrichedSize)

	// Header
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventIO))
	binary.LittleEndian.PutUint32(data[4:8], 1000)         // pid
	binary.LittleEndian.PutUint32(data[8:12], 1001)        // tid
	binary.LittleEndian.PutUint64(data[16:24], 5000000000) // timestamp

	// IO fields
	binary.LittleEndian.PutUint32(data[24:28], 1)       // op = read
	binary.LittleEndian.PutUint32(data[28:32], 7)       // fd = 7
	binary.LittleEndian.PutUint64(data[32:40], 4096)    // bytes
	binary.LittleEndian.PutUint64(data[40:48], 2000000) // latency = 2ms

	// Socket enrichment
	data[48] = 2                                           // fd_type = TCP
	data[49] = 1                                           // sock_state = TCP_ESTABLISHED
	binary.LittleEndian.PutUint16(data[50:52], 54321)      // local_port
	binary.LittleEndian.PutUint16(data[52:54], 3306)       // remote_port
	binary.LittleEndian.PutUint32(data[56:60], 0x0100A8C0) // local = 192.168.0.1
	binary.LittleEndian.PutUint32(data[60:64], 0x0100000A) // remote = 10.0.0.1

	// TCP stats
	binary.LittleEndian.PutUint32(data[64:68], 500)      // srtt_us
	binary.LittleEndian.PutUint32(data[68:72], 10)       // snd_cwnd
	binary.LittleEndian.PutUint32(data[72:76], 3)        // total_retrans
	binary.LittleEndian.PutUint32(data[76:80], 5)        // packets_out
	binary.LittleEndian.PutUint32(data[80:84], 1)        // retrans_out
	binary.LittleEndian.PutUint32(data[84:88], 0)        // lost_out
	binary.LittleEndian.PutUint32(data[88:92], 65535)    // rcv_wnd
	binary.LittleEndian.PutUint64(data[96:104], 100000)  // bytes_sent
	binary.LittleEndian.PutUint64(data[104:112], 500000) // bytes_received

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	io, ok := evt.(*IOEvent)
	if !ok {
		t.Fatalf("expected *IOEvent, got %T", evt)
	}

	if io.PID != 1000 {
		t.Errorf("PID: got %d, want 1000", io.PID)
	}
	if io.TID != 1001 {
		t.Errorf("TID: got %d, want 1001", io.TID)
	}
	if io.Op != 1 {
		t.Errorf("Op: got %d, want 1", io.Op)
	}
	if io.FD != 7 {
		t.Errorf("FD: got %d, want 7", io.FD)
	}
	if io.Bytes != 4096 {
		t.Errorf("Bytes: got %d, want 4096", io.Bytes)
	}
	if io.LatencyNs != 2000000 {
		t.Errorf("LatencyNs: got %d, want 2000000", io.LatencyNs)
	}

	// Socket info
	if io.FdType != 2 {
		t.Errorf("FdType: got %d, want 2 (TCP)", io.FdType)
	}
	if io.LocalPort != 54321 {
		t.Errorf("LocalPort: got %d, want 54321", io.LocalPort)
	}
	if io.RemotePort != 3306 {
		t.Errorf("RemotePort: got %d, want 3306", io.RemotePort)
	}

	// FdInfo formatting
	info := io.FormatFdInfo()
	if info != "tcp:192.168.0.1:54321→10.0.0.1:3306" {
		t.Errorf("FormatFdInfo: got %q", info)
	}

	// TCP stats
	if io.TCPStats == nil {
		t.Fatal("TCPStats is nil")
	}
	if io.TCPStats.SrttUs != 500 {
		t.Errorf("SrttUs: got %d, want 500", io.TCPStats.SrttUs)
	}
	if io.TCPStats.SndCwnd != 10 {
		t.Errorf("SndCwnd: got %d, want 10", io.TCPStats.SndCwnd)
	}
	if io.TCPStats.TotalRetrans != 3 {
		t.Errorf("TotalRetrans: got %d, want 3", io.TCPStats.TotalRetrans)
	}
	if io.TCPStats.BytesSent != 100000 {
		t.Errorf("BytesSent: got %d, want 100000", io.TCPStats.BytesSent)
	}
	if io.TCPStats.BytesReceived != 500000 {
		t.Errorf("BytesReceived: got %d, want 500000", io.TCPStats.BytesReceived)
	}
}

func TestParseEvent_IOEnrichedFileType(t *testing.T) {
	data := make([]byte, ioEventEnrichedSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventIO))
	binary.LittleEndian.PutUint32(data[4:8], 1000)
	binary.LittleEndian.PutUint32(data[8:12], 1001)
	binary.LittleEndian.PutUint64(data[16:24], 1000)
	binary.LittleEndian.PutUint32(data[24:28], 1)     // read
	binary.LittleEndian.PutUint32(data[28:32], 5)     // fd
	binary.LittleEndian.PutUint64(data[32:40], 512)   // bytes
	binary.LittleEndian.PutUint64(data[40:48], 50000) // latency

	data[48] = 1 // fd_type = FILE

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	io := evt.(*IOEvent)
	if io.FdType != 1 {
		t.Errorf("FdType: got %d, want 1 (FILE)", io.FdType)
	}
	if io.FormatFdInfo() != "file" {
		t.Errorf("FormatFdInfo: got %q, want %q", io.FormatFdInfo(), "file")
	}
	if io.TCPStats != nil {
		t.Errorf("TCPStats should be nil for file, got %+v", io.TCPStats)
	}
}

func TestIoOpName(t *testing.T) {
	tests := map[uint32]string{
		IoOpRead:     "read",
		IoOpWrite:    "write",
		IoOpSendto:   "sendto",
		IoOpRecvfrom: "recvfrom",
		IoOpConnect:  "connect",
		99:           "syscall_99",
	}
	for op, want := range tests {
		got := IoOpName(op)
		if got != want {
			t.Errorf("IoOpName(%d): got %q, want %q", op, got, want)
		}
	}
}

func TestFormatIPv4(t *testing.T) {
	// 10.0.0.1 in network byte order = 0x0100000A
	got := formatIPv4(0x0100000A)
	if got != "10.0.0.1" {
		t.Errorf("formatIPv4(0x0100000A): got %q, want %q", got, "10.0.0.1")
	}

	// 192.168.0.100 in network byte order = 0x6400A8C0
	got = formatIPv4(0x6400A8C0)
	if got != "192.168.0.100" {
		t.Errorf("formatIPv4(0x6400A8C0): got %q, want %q", got, "192.168.0.100")
	}
}

func TestParseEvent_RubySampleWithNativeStack(t *testing.T) {
	stackData := buildTestStackData("Trilogy#query", "/app/db.rb", 42)

	// Build event with native stack IPs at fixed offset (header + MAX_STACK_SIZE)
	nativeIPs := []uint64{0x7f001000, 0x7f002000, 0x7f003000} // 3 native IPs
	nativeStackBytes := len(nativeIPs) * 8

	totalSize := rubySampleHeaderSize + maxRubyStackSize + nativeStackBytes
	data := make([]byte, totalSize)

	// Header
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(data[4:8], 100)                        // pid
	binary.LittleEndian.PutUint32(data[8:12], 200)                       // tid
	binary.LittleEndian.PutUint32(data[12:16], 1)                        // weight
	binary.LittleEndian.PutUint64(data[16:24], 1000)                     // timestamp
	binary.LittleEndian.PutUint64(data[24:32], 42)                       // thread_id
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(stackData)))   // stack_data_len
	binary.LittleEndian.PutUint32(data[36:40], uint32(nativeStackBytes)) // native_stack_len

	// Ruby stack data at offset 40
	copy(data[rubySampleHeaderSize:], stackData)

	// Native IPs at fixed offset (40 + 4096 = 4136)
	nativeOff := rubySampleHeaderSize + maxRubyStackSize
	for i, ip := range nativeIPs {
		binary.LittleEndian.PutUint64(data[nativeOff+i*8:nativeOff+i*8+8], ip)
	}

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	sample := evt.(*RubySampleEvent)

	// Verify Ruby stack parsed correctly
	if len(sample.StackData) == 0 {
		t.Fatal("StackData is empty")
	}
	frames := ParseInlineStack(sample.StackData)
	if len(frames) != 1 || frames[0].Label != "Trilogy#query" {
		t.Errorf("Ruby stack: got %v", frames)
	}

	// Verify native IPs parsed
	if len(sample.NativeStackIPs) != 3 {
		t.Fatalf("NativeStackIPs: got %d, want 3", len(sample.NativeStackIPs))
	}
	if sample.NativeStackIPs[0] != 0x7f001000 {
		t.Errorf("NativeStackIPs[0]: got 0x%x, want 0x7f001000", sample.NativeStackIPs[0])
	}
	if sample.NativeStackIPs[2] != 0x7f003000 {
		t.Errorf("NativeStackIPs[2]: got 0x%x, want 0x7f003000", sample.NativeStackIPs[2])
	}
}

func TestParseEvent_RubySampleNoNativeStack(t *testing.T) {
	// Events without native stack (native_stack_len = 0) should still work
	stackData := buildTestStackData("Object#foo", "/app/foo.rb", 1)
	totalSize := rubySampleHeaderSize + len(stackData)
	data := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(data[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(data[4:8], 100)
	binary.LittleEndian.PutUint32(data[8:12], 200)
	binary.LittleEndian.PutUint32(data[12:16], 1)
	binary.LittleEndian.PutUint64(data[16:24], 1000)
	binary.LittleEndian.PutUint64(data[24:32], 42)
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(stackData)))
	binary.LittleEndian.PutUint32(data[36:40], 0) // native_stack_len = 0
	copy(data[rubySampleHeaderSize:], stackData)

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	sample := evt.(*RubySampleEvent)
	if len(sample.NativeStackIPs) != 0 {
		t.Errorf("expected no native IPs, got %d", len(sample.NativeStackIPs))
	}
}

func TestParseGVLWaitEvent(t *testing.T) {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventGVLWait))
	binary.LittleEndian.PutUint32(data[4:8], 1234)         // pid
	binary.LittleEndian.PutUint32(data[8:12], 5678)        // tid
	binary.LittleEndian.PutUint32(data[12:16], 0)          // pad
	binary.LittleEndian.PutUint64(data[16:24], 5_000_000)  // wait_ns = 5ms
	binary.LittleEndian.PutUint64(data[24:32], 99_000_000) // timestamp_ns
	binary.LittleEndian.PutUint64(data[32:40], 0xdeadbeef) // thread_value

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	gvl, ok := evt.(*GVLWaitEvent)
	if !ok {
		t.Fatalf("expected *GVLWaitEvent, got %T", evt)
	}

	if gvl.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", gvl.PID)
	}
	if gvl.TID != 5678 {
		t.Errorf("TID: got %d, want 5678", gvl.TID)
	}
	if gvl.WaitNs != 5_000_000 {
		t.Errorf("WaitNs: got %d, want 5000000", gvl.WaitNs)
	}
	if gvl.TimestampNs != 99_000_000 {
		t.Errorf("TimestampNs: got %d, want 99000000", gvl.TimestampNs)
	}
	if gvl.ThreadValue != 0xdeadbeef {
		t.Errorf("ThreadValue: got %x, want deadbeef", gvl.ThreadValue)
	}
}

func TestParseGVLWaitEvent_TooShort(t *testing.T) {
	data := make([]byte, 20) // too short for 40-byte event
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventGVLWait))

	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for short GVL event")
	}
}

func TestParseGVLStateChangeEvent(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventGVLState))
	binary.LittleEndian.PutUint32(data[4:8], 1234)                      // pid
	binary.LittleEndian.PutUint32(data[8:12], 5678)                     // tid
	binary.LittleEndian.PutUint32(data[12:16], uint32(GVLStateStalled)) // gvl_state
	binary.LittleEndian.PutUint64(data[16:24], 99_000_000)              // timestamp_ns
	binary.LittleEndian.PutUint64(data[24:32], 0xdeadbeef)              // thread_value

	evt, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	gvl, ok := evt.(*GVLStateChangeEvent)
	if !ok {
		t.Fatalf("expected *GVLStateChangeEvent, got %T", evt)
	}

	if gvl.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", gvl.PID)
	}
	if gvl.TID != 5678 {
		t.Errorf("TID: got %d, want 5678", gvl.TID)
	}
	if gvl.GVLState != GVLStateStalled {
		t.Errorf("GVLState: got %d, want %d", gvl.GVLState, GVLStateStalled)
	}
	if gvl.TimestampNs != 99_000_000 {
		t.Errorf("TimestampNs: got %d, want 99000000", gvl.TimestampNs)
	}
	if gvl.ThreadValue != 0xdeadbeef {
		t.Errorf("ThreadValue: got %x, want deadbeef", gvl.ThreadValue)
	}
}

func TestParseGVLStateChangeEvent_TooShort(t *testing.T) {
	data := make([]byte, 20) // too short for 32-byte event
	binary.LittleEndian.PutUint32(data[0:4], uint32(EventGVLState))

	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for short GVL state event")
	}
}

func TestParseEvent_RubyAlloc(t *testing.T) {
	// Build a minimal alloc event with metadata at fixed offset.
	// Header: 40 bytes, then stack data, then native IPs at maxRubyStackSize,
	// then alloc metadata at allocMetaOffset.
	buf := make([]byte, allocMetaOffset+12+6)                       // 6 bytes for "String"
	binary.LittleEndian.PutUint32(buf[0:4], uint32(EventRubyAlloc)) // type
	binary.LittleEndian.PutUint32(buf[4:8], 1234)                   // pid
	binary.LittleEndian.PutUint32(buf[8:12], 5678)                  // tid
	binary.LittleEndian.PutUint32(buf[12:16], 1)                    // weight
	binary.LittleEndian.PutUint64(buf[16:24], 999000000)            // timestamp
	binary.LittleEndian.PutUint64(buf[24:32], 42)                   // thread_id
	binary.LittleEndian.PutUint32(buf[32:36], 0)                    // stack_data_len
	binary.LittleEndian.PutUint32(buf[36:40], 0)                    // native_stack_len

	// Alloc metadata at fixed offset
	binary.LittleEndian.PutUint32(buf[allocMetaOffset:], 6)    // type_name_len
	binary.LittleEndian.PutUint64(buf[allocMetaOffset+4:], 40) // alloc_size
	copy(buf[allocMetaOffset+12:], "String")                   // type_name

	event, err := ParseEvent(buf)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}

	alloc, ok := event.(*RubyAllocEvent)
	if !ok {
		t.Fatalf("expected *RubyAllocEvent, got %T", event)
	}
	if alloc.ObjectType != "String" {
		t.Errorf("ObjectType: got %q, want %q", alloc.ObjectType, "String")
	}
	if alloc.SizeBytes != 40 {
		t.Errorf("SizeBytes: got %d, want 40", alloc.SizeBytes)
	}
	if alloc.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", alloc.PID)
	}
}
