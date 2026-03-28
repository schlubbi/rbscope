package collector

import "testing"

// FuzzParseEvent tests the event parser against arbitrary input.
// Run: go test -fuzz=FuzzParseEvent -fuzztime=30s ./pkg/collector/
func FuzzParseEvent(f *testing.F) {
	// Seed with valid event headers for each type
	for _, et := range []EventType{EventRubySample, EventRubySpan, EventIO, EventSched} {
		seed := make([]byte, 128)
		seed[0] = byte(et)
		// pid
		seed[4] = 1
		// timestamp
		seed[12] = 1
		f.Add(seed)
	}

	// Seed with truncated and empty inputs
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	f.Add(make([]byte, eventHeaderSize))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// ParseEvent should never panic on any input
		_, _ = ParseEvent(data)
	})
}
