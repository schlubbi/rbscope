package export

import (
	"sync"

	"github.com/google/pprof/profile"
)

// PprofBuilder accumulates stack samples and produces a pprof Profile.
type PprofBuilder struct {
	mu       sync.Mutex
	strings  map[string]int64 // dedup string table
	locs     map[uint64]*profile.Location
	samples  []*profile.Sample
	locID    uint64
	period   int64
	durationNanos int64
}

// NewPprofBuilder creates a builder. period is the sampling period in
// nanoseconds (e.g. 1e9/19 for 19 Hz).
func NewPprofBuilder(periodNanos int64) *PprofBuilder {
	return &PprofBuilder{
		strings: make(map[string]int64),
		locs:    make(map[uint64]*profile.Location),
		period:  periodNanos,
	}
}

// AddSample records a single stack sample.
func (b *PprofBuilder) AddSample(stackID uint32, labels map[string]string, value int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	addr := uint64(stackID)
	loc := b.getOrCreateLoc(addr)

	labelSet := make(map[string][]string, len(labels))
	for k, v := range labels {
		labelSet[k] = []string{v}
	}

	s := &profile.Sample{
		Location: []*profile.Location{loc},
		Value:    []int64{value},
		Label:    labelSet,
	}
	b.samples = append(b.samples, s)
}

// Build produces the accumulated profile and returns it. The builder is NOT
// reset—call Flush for build-and-reset semantics.
func (b *PprofBuilder) Build() *profile.Profile {
	b.mu.Lock()
	defer b.mu.Unlock()

	locations := make([]*profile.Location, 0, len(b.locs))
	for _, loc := range b.locs {
		locations = append(locations, loc)
	}

	p := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
		},
		Sample:   b.samples,
		Location: locations,
		Period:   b.period,
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		DurationNanos: b.durationNanos,
	}
	return p
}

// Flush builds the profile, resets internal state, and returns the profile.
func (b *PprofBuilder) Flush() *profile.Profile {
	p := b.Build()

	b.mu.Lock()
	b.samples = nil
	b.locs = make(map[uint64]*profile.Location)
	b.strings = make(map[string]int64)
	b.mu.Unlock()

	return p
}

// SetDuration records the wall-clock duration for the current interval.
func (b *PprofBuilder) SetDuration(nanos int64) {
	b.mu.Lock()
	b.durationNanos = nanos
	b.mu.Unlock()
}

func (b *PprofBuilder) getOrCreateLoc(addr uint64) *profile.Location {
	if loc, ok := b.locs[addr]; ok {
		return loc
	}
	b.locID++
	loc := &profile.Location{
		ID:      b.locID,
		Address: addr,
	}
	b.locs[addr] = loc
	return loc
}
