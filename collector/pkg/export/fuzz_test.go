package export

import "testing"

// FuzzPprofBuilder tests the pprof builder against random inputs.
// Run: go test -fuzz=FuzzPprofBuilder -fuzztime=30s ./pkg/export/
func FuzzPprofBuilder(f *testing.F) {
	f.Add(uint32(1), "trace123", int64(1))
	f.Add(uint32(0), "", int64(0))
	f.Add(uint32(65535), "very-long-trace-id-value-1234567890", int64(999))

	f.Fuzz(func(t *testing.T, stackID uint32, traceID string, value int64) {
		b := NewPprofBuilder(int64(52631578))

		labels := map[string]string{}
		if traceID != "" {
			labels["trace_id"] = traceID
		}
		b.AddSample(stackID, labels, value)
		b.AddSample(stackID, nil, value)

		p := b.Flush()
		if p == nil {
			t.Fatal("Flush returned nil")
		}
		if len(p.Sample) != 2 {
			t.Fatalf("expected 2 samples, got %d", len(p.Sample))
		}
	})
}
