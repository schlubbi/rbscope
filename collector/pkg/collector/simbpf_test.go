package collector

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestSimBPF_RoundTrip(t *testing.T) {
	sim := NewSimBPF(99)

	if err := sim.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := sim.AttachPID(42); err != nil {
		t.Fatalf("AttachPID: %v", err)
	}

	// Read events from the ring buffer
	buf := make([]byte, 8192)
	var events [][]byte

	deadline := time.After(2 * time.Second)
	for len(events) < 5 {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for events, got %d", len(events))
		default:
		}

		n, err := sim.ReadRingBuffer(buf)
		if err != nil {
			t.Fatalf("ReadRingBuffer: %v", err)
		}
		if n > 0 {
			event := make([]byte, n)
			copy(event, buf[:n])
			events = append(events, event)
		}
	}

	// Verify each event round-trips through ParseEvent
	for i, raw := range events {
		evt, err := ParseEvent(raw)
		if err != nil {
			t.Fatalf("event %d: ParseEvent failed: %v", i, err)
		}

		sample, ok := evt.(*RubySampleEvent)
		if !ok {
			t.Fatalf("event %d: expected *RubySampleEvent, got %T", i, evt)
		}

		if sample.PID != 42 {
			t.Errorf("event %d: PID: got %d, want 42", i, sample.PID)
		}

		// Stack data should be parseable as inline format v2
		frames := ParseInlineStack(sample.StackData)
		if len(frames) == 0 {
			t.Errorf("event %d: expected frames from inline stack, got 0", i)
			continue
		}

		if sample.StackDataLen != uint32(len(sample.StackData)) {
			t.Errorf("event %d: StackDataLen=%d but data len=%d",
				i, sample.StackDataLen, len(sample.StackData))
		}

		// Each frame should have non-empty label and path
		for j, frame := range frames {
			if frame.Label == "" {
				t.Errorf("event %d frame %d: empty label", i, j)
			}
			if frame.Path == "" {
				t.Errorf("event %d frame %d: empty path", i, j)
			}
		}
	}

	if err := sim.DetachPID(42); err != nil {
		t.Fatalf("DetachPID: %v", err)
	}
	if err := sim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSimBPF_FormatV2Header(t *testing.T) {
	sim := NewSimBPF(99)
	_ = sim.Load()
	_ = sim.AttachPID(100)

	buf := make([]byte, 8192)
	var raw []byte

	deadline := time.After(2 * time.Second)
	for raw == nil {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for event")
		default:
		}
		n, _ := sim.ReadRingBuffer(buf)
		if n > 0 {
			raw = make([]byte, n)
			copy(raw, buf[:n])
		}
	}
	_ = sim.Close()

	// Verify 40-byte header structure
	if len(raw) < rubySampleHeaderSize {
		t.Fatalf("event too short: %d bytes, need at least %d", len(raw), rubySampleHeaderSize)
	}

	eventType := binary.LittleEndian.Uint32(raw[0:4])
	if eventType != uint32(EventRubySample) {
		t.Errorf("event type: got %d, want %d", eventType, EventRubySample)
	}

	pid := binary.LittleEndian.Uint32(raw[4:8])
	if pid != 100 {
		t.Errorf("PID: got %d, want 100", pid)
	}

	stackDataLen := binary.LittleEndian.Uint32(raw[32:36])
	expectedDataLen := uint32(len(raw) - rubySampleHeaderSize)
	if stackDataLen != expectedDataLen {
		t.Errorf("stack_data_len: got %d, want %d", stackDataLen, expectedDataLen)
	}

	// Verify inline stack starts with version byte 2
	if raw[rubySampleHeaderSize] != 2 {
		t.Errorf("inline stack version: got %d, want 2", raw[rubySampleHeaderSize])
	}
}

func TestSimBPF_AllStacksRoundTrip(t *testing.T) {
	// Verify every stack in SimStackNames produces valid inline data
	for stackID, frameNames := range SimStackNames {
		var stackData []byte
		stackData = append(stackData, 2)
		stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(frameNames)))

		for i, name := range frameNames {
			stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(name)))
			stackData = append(stackData, name...)
			path := "app/models/" + name[:min(len(name), 20)] + ".rb"
			stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(path)))
			stackData = append(stackData, path...)
			stackData = binary.LittleEndian.AppendUint32(stackData, uint32(10+i*5))
		}

		frames := ParseInlineStack(stackData)
		if len(frames) != len(frameNames) {
			t.Errorf("stack %d: expected %d frames, got %d", stackID, len(frameNames), len(frames))
			continue
		}

		for i, frame := range frames {
			if frame.Label != frameNames[i] {
				t.Errorf("stack %d frame %d: got label %q, want %q", stackID, i, frame.Label, frameNames[i])
			}
		}
	}
}

func TestSimBPF_AttachDetach(t *testing.T) {
	sim := NewSimBPF(99)

	if err := sim.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := sim.AttachPID(123); err != nil {
		t.Fatalf("AttachPID: %v", err)
	}
	if sim.pid != 123 {
		t.Errorf("pid after attach: got %d, want 123", sim.pid)
	}
	if err := sim.DetachPID(123); err != nil {
		t.Fatalf("DetachPID: %v", err)
	}
	if err := sim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSimBPF_GeneratesIOEvents(t *testing.T) {
	sim := NewSimBPF(100)
	if err := sim.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := sim.AttachPID(42); err != nil {
		t.Fatalf("AttachPID: %v", err)
	}

	buf := make([]byte, 64*1024)
	var ioCount, sampleCount int

	// Collect events for ~200ms
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, err := sim.ReadRingBuffer(buf)
		if err != nil || n == 0 {
			continue
		}
		evt, err := ParseEvent(buf[:n])
		if err != nil {
			continue
		}
		switch evt.(type) {
		case *RubySampleEvent:
			sampleCount++
		case *IOEvent:
			ioCount++
		}
	}

	if err := sim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if sampleCount == 0 {
		t.Error("expected stack samples from SimBPF")
	}
	if ioCount == 0 {
		t.Error("expected IO events from SimBPF")
	}
}

func TestSimBPF_IOEventParsesCorrectly(t *testing.T) {
	sim := NewSimBPF(500) // higher freq for faster test
	if err := sim.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := sim.AttachPID(42); err != nil {
		t.Fatalf("AttachPID: %v", err)
	}

	buf := make([]byte, 64*1024)
	var foundTCP bool

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, err := sim.ReadRingBuffer(buf)
		if err != nil || n == 0 {
			continue
		}
		evt, err := ParseEvent(buf[:n])
		if err != nil {
			continue
		}
		io, ok := evt.(*IOEvent)
		if !ok {
			continue
		}
		if io.FdType == 2 { // TCP
			foundTCP = true
			if io.RemotePort == 0 {
				t.Error("TCP IO event has RemotePort=0")
			}
			if io.TcpStats == nil {
				t.Error("TCP IO event has nil TcpStats")
			} else if io.TcpStats.SrttUs == 0 {
				t.Error("TCP IO event has SrttUs=0")
			}
			info := io.FormatFdInfo()
			if info == "" {
				t.Error("TCP IO event has empty FormatFdInfo")
			}
			break
		}
	}

	if err := sim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !foundTCP {
		t.Error("expected at least one TCP IO event")
	}
}
