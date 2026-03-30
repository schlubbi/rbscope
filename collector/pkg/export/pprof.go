package export

import (
	"github.com/google/pprof/profile"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// CaptureToProfile converts a built rbscope Capture into a pprof Profile.
// This produces unified stacks (Ruby + native C extension + syscall) because
// the Capture has already gone through Builder.Build() which synthesizes
// I/O samples with cross-referenced native and Ruby frames.
func CaptureToProfile(capture *pb.Capture) *profile.Profile {
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: "nanoseconds"},
		},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:     int64(10_000_000), // 10ms = 100Hz equivalent
	}

	// Build lookup tables for strings and frames from the Capture.
	funcMap := make(map[string]*profile.Function)
	locMap := make(map[uint64]*profile.Location)
	var funcID, locID uint64

	getOrCreateFunc := func(name, filename string) *profile.Function {
		key := name + "\x00" + filename
		if fn, ok := funcMap[key]; ok {
			return fn
		}
		funcID++
		fn := &profile.Function{
			ID:       funcID,
			Name:     name,
			Filename: filename,
		}
		funcMap[key] = fn
		prof.Function = append(prof.Function, fn)
		return fn
	}

	getOrCreateLoc := func(name, filename string, line int64) *profile.Location {
		addr := hashName(name + filename)
		if loc, ok := locMap[addr]; ok {
			return loc
		}
		fn := getOrCreateFunc(name, filename)
		locID++
		loc := &profile.Location{
			ID:      locID,
			Address: addr,
			Line:    []profile.Line{{Function: fn, Line: line}},
		}
		locMap[addr] = loc
		prof.Location = append(prof.Location, loc)
		return loc
	}

	// Resolve a frame index to name and path using the Capture's tables.
	resolveFrame := func(frameIdx uint32) (string, string, int64) {
		if int(frameIdx) >= len(capture.FrameTable) {
			return "<unknown>", "", 0
		}
		f := capture.FrameTable[frameIdx]
		name := lookupString(capture.StringTable, f.FunctionNameIdx)
		path := lookupString(capture.StringTable, f.FileNameIdx)
		return name, path, int64(f.LineNumber)
	}

	for _, thread := range capture.Threads {
		for _, sample := range thread.Samples {
			if len(sample.FrameIds) == 0 {
				continue
			}

			locs := make([]*profile.Location, 0, len(sample.FrameIds))
			for _, fid := range sample.FrameIds {
				name, path, line := resolveFrame(fid)
				if name == "" {
					name = "<unknown>"
				}
				locs = append(locs, getOrCreateLoc(name, path, line))
			}

			prof.Sample = append(prof.Sample, &profile.Sample{
				Location: locs,
				Value:    []int64{int64(sample.Weight), int64(sample.Weight) * 10_000_000},
			})
		}
	}

	return prof
}

func lookupString(table []string, idx uint32) string {
	if int(idx) >= len(table) {
		return ""
	}
	return table[idx]
}

// CaptureToAllocProfile converts allocation samples from a Capture into a
// pprof Profile with alloc_objects/alloc_space value types.
// Returns nil if there are no allocation samples.
func CaptureToAllocProfile(capture *pb.Capture) *profile.Profile {
	hasAllocs := false
	for _, thread := range capture.Threads {
		if len(thread.Allocations) > 0 {
			hasAllocs = true
			break
		}
	}
	if !hasAllocs {
		return nil
	}

	prof := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "alloc_objects", Unit: "count"},
			{Type: "alloc_space", Unit: "bytes"},
		},
		PeriodType: &profile.ValueType{Type: "space", Unit: "bytes"},
		Period:     1,
	}

	funcMap := make(map[string]*profile.Function)
	locMap := make(map[uint64]*profile.Location)
	var funcID, locID uint64

	getOrCreateFunc := func(name, filename string) *profile.Function {
		key := name + "\x00" + filename
		if fn, ok := funcMap[key]; ok {
			return fn
		}
		funcID++
		fn := &profile.Function{
			ID:       funcID,
			Name:     name,
			Filename: filename,
		}
		funcMap[key] = fn
		prof.Function = append(prof.Function, fn)
		return fn
	}

	getOrCreateLoc := func(name, filename string, line int64) *profile.Location {
		addr := hashName(name + filename)
		if loc, ok := locMap[addr]; ok {
			return loc
		}
		fn := getOrCreateFunc(name, filename)
		locID++
		loc := &profile.Location{
			ID:      locID,
			Address: addr,
			Line:    []profile.Line{{Function: fn, Line: line}},
		}
		locMap[addr] = loc
		prof.Location = append(prof.Location, loc)
		return loc
	}

	resolveFrame := func(frameIdx uint32) (string, string, int64) {
		if int(frameIdx) >= len(capture.FrameTable) {
			return "<unknown>", "", 0
		}
		f := capture.FrameTable[frameIdx]
		name := lookupString(capture.StringTable, f.FunctionNameIdx)
		path := lookupString(capture.StringTable, f.FileNameIdx)
		return name, path, int64(f.LineNumber)
	}

	for _, thread := range capture.Threads {
		for _, alloc := range thread.Allocations {
			if len(alloc.FrameIds) == 0 {
				continue
			}

			locs := make([]*profile.Location, 0, len(alloc.FrameIds))
			for _, fid := range alloc.FrameIds {
				name, path, line := resolveFrame(fid)
				if name == "" {
					name = "<unknown>"
				}
				locs = append(locs, getOrCreateLoc(name, path, line))
			}

			prof.Sample = append(prof.Sample, &profile.Sample{
				Location: locs,
				Value:    []int64{1, int64(alloc.SizeBytes)}, //nolint:gosec // size fits int64
			})
		}
	}

	return prof
}
