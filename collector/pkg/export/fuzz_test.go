package export

import (
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// FuzzCaptureToProfile tests the Capture→pprof converter with random inputs.
// Run: go test -fuzz=FuzzCaptureToProfile -fuzztime=30s ./pkg/export/
func FuzzCaptureToProfile(f *testing.F) {
	f.Add(uint32(0), uint32(0), uint32(1))
	f.Add(uint32(1), uint32(2), uint32(3))
	f.Add(uint32(100), uint32(50), uint32(10))

	f.Fuzz(func(t *testing.T, nameIdx, fileIdx, weight uint32) {
		capture := &pb.Capture{
			StringTable: []string{"", "func_a", "file.rb", "func_b"},
			FrameTable: []*pb.StackFrame{
				{FunctionNameIdx: nameIdx % 4, FileNameIdx: fileIdx % 4},
			},
			Threads: []*pb.ThreadTimeline{
				{
					ThreadId: 1,
					Samples: []*pb.Sample{
						{FrameIds: []uint32{0}, Weight: weight},
					},
				},
			},
		}

		prof := CaptureToProfile(capture)
		if prof == nil {
			t.Fatal("CaptureToProfile returned nil")
		}
		if len(prof.Sample) != 1 {
			t.Fatalf("expected 1 sample, got %d", len(prof.Sample))
		}
	})
}
