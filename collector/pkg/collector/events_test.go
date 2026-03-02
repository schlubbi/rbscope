package collector

import (
	"testing"
)

func TestParseEvent_RubySample(t *testing.T) {
	// Header: type(4) + pid(4) + tid(4) + timestamp(8) + cpu(4) = 24 bytes
	// Sample body: stackID(4) + stackLen(4) + traceID(16) + spanID(8) + threadID(8) = 40 bytes
	// Total minimum: 64 bytes
	data := make([]byte, 64)

	// event_type = 1 (RubySample)
	data[0] = byte(EventRubySample)

	// pid = 1234 (little-endian at offset 4)
	data[4] = 0xD2
	data[5] = 0x04

	// tid = 5678 (little-endian at offset 8)
	data[8] = 0x2E
	data[9] = 0x16

	// timestamp = 1000000000 (offset 12, 8 bytes LE)
	data[12] = 0x00
	data[13] = 0xCA
	data[14] = 0x9A
	data[15] = 0x3B

	// cpu = 0 (offset 20)

	// stackID = 42 (offset 24)
	data[24] = 42

	// stackLen = 3 (offset 28)
	data[28] = 3

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
	if sample.StackID != 42 {
		t.Errorf("StackID: got %d, want 42", sample.StackID)
	}
	if sample.StackLen != 3 {
		t.Errorf("StackLen: got %d, want 3", sample.StackLen)
	}
}

func TestParseEvent_IO(t *testing.T) {
	// Header(24) + fd(4) + op(4) + bytes(8) + latency(8) = 48
	data := make([]byte, 48)
	data[0] = byte(EventIO)

	// pid = 100 (offset 4)
	data[4] = 100

	// fd = 5 (offset 24, after header)
	data[24] = 5

	// op = 1 (read, offset 28)
	data[28] = 1

	// bytes = 4096 (offset 32)
	data[32] = 0x00
	data[33] = 0x10

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
	data[0] = 99 // unknown event type

	_, err := ParseEvent(data)
	if err == nil {
		t.Error("expected error for unknown event type")
	}
}

func TestParseEvent_Sched(t *testing.T) {
	// Header(24) + prevPID(4) + nextPID(4) + offCPU(8) + runqLat(8) = 48
	data := make([]byte, 48)
	data[0] = byte(EventSched)

	// prevPID = 200 (offset 24)
	data[24] = 200

	// nextPID = 300 (offset 28)
	data[28] = 0x2C
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
