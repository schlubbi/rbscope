package collector

import (
"encoding/binary"
"testing"
)

func TestParseEvent_RubySample(t *testing.T) {
// New BPF layout: type(4) + pid(4) + tid(4) + _pad0(4) + timestamp_ns(8) +
// thread_id(8) + stack_data_len(4) + _pad1(4) = 40 bytes header
// Plus inline stack data follows
stackData := buildTestStackData("Object#foo", "/app/test.rb", 42)
totalSize := rubySampleHeaderSize + len(stackData)
data := make([]byte, totalSize)

binary.LittleEndian.PutUint32(data[0:4], uint32(EventRubySample))
binary.LittleEndian.PutUint32(data[4:8], 1234)
binary.LittleEndian.PutUint32(data[8:12], 5678)
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
data[24] = 200          // prevPID
data[28] = 0x2C         // nextPID = 300
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
