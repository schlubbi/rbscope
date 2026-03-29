package export

import (
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func TestCaptureToProfile(t *testing.T) {
	capture := &pb.Capture{
		StringTable: []string{
			"",                                    // 0: empty
			"PostsController#index",               // 1
			"app/controllers/posts_controller.rb", // 2
			"Trilogy#query",                       // 3
			"(unknown)",                           // 4
			"rb_trilogy_query",                    // 5
			"/gems/trilogy/cext.so",               // 6
			"write",                               // 7
			"/usr/lib/libc.so.6",                  // 8
		},
		FrameTable: []*pb.StackFrame{
			{FunctionNameIdx: 1, FileNameIdx: 2, LineNumber: 10}, // 0: PostsController#index
			{FunctionNameIdx: 3, FileNameIdx: 4, LineNumber: 0},  // 1: Trilogy#query
			{FunctionNameIdx: 5, FileNameIdx: 6, LineNumber: 0},  // 2: rb_trilogy_query (native)
			{FunctionNameIdx: 7, FileNameIdx: 8, LineNumber: 0},  // 3: write (native)
		},
		Threads: []*pb.ThreadTimeline{
			{
				ThreadId: 100,
				Samples: []*pb.Sample{
					{
						TimestampNs: 1_000_000_000,
						FrameIds:    []uint32{0, 1}, // Controller → Trilogy (Ruby only)
						Weight:      1,
					},
					{
						TimestampNs: 1_001_000_000,
						FrameIds:    []uint32{3, 2, 1, 0}, // write → rb_trilogy → Trilogy → Controller (unified)
						Weight:      1,
						IsIoSample:  true,
					},
				},
			},
		},
	}

	prof := CaptureToProfile(capture)

	if len(prof.Sample) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(prof.Sample))
	}

	// First sample: Ruby-only (2 locations)
	s0 := prof.Sample[0]
	if len(s0.Location) != 2 {
		t.Fatalf("sample[0]: expected 2 locations, got %d", len(s0.Location))
	}
	if s0.Location[0].Line[0].Function.Name != "PostsController#index" {
		t.Errorf("sample[0] loc[0] = %q, want PostsController#index", s0.Location[0].Line[0].Function.Name)
	}

	// Second sample: unified (4 locations: write → rb_trilogy → Trilogy → Controller)
	s1 := prof.Sample[1]
	if len(s1.Location) != 4 {
		t.Fatalf("sample[1]: expected 4 locations, got %d", len(s1.Location))
	}
	names := make([]string, len(s1.Location))
	for i, loc := range s1.Location {
		names[i] = loc.Line[0].Function.Name
	}
	expected := []string{"write", "rb_trilogy_query", "Trilogy#query", "PostsController#index"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("sample[1] loc[%d] = %q, want %q", i, names[i], want)
		}
	}

	// Weight should map to value
	if s1.Value[0] != 1 {
		t.Errorf("sample[1] count = %d, want 1", s1.Value[0])
	}

	// Dedup: same function name shouldn't create duplicate Function entries
	funcCount := make(map[string]int)
	for _, fn := range prof.Function {
		funcCount[fn.Name]++
	}
	for name, count := range funcCount {
		if count > 1 {
			t.Errorf("function %q appears %d times (should be deduped)", name, count)
		}
	}
}

func TestCaptureToProfile_Empty(t *testing.T) {
	capture := &pb.Capture{}
	prof := CaptureToProfile(capture)
	if len(prof.Sample) != 0 {
		t.Errorf("expected 0 samples for empty capture, got %d", len(prof.Sample))
	}
}

func TestCaptureToProfile_WeightExpansion(t *testing.T) {
	capture := &pb.Capture{
		StringTable: []string{"", "foo", "bar.rb"},
		FrameTable:  []*pb.StackFrame{{FunctionNameIdx: 1, FileNameIdx: 2}},
		Threads: []*pb.ThreadTimeline{
			{
				ThreadId: 1,
				Samples: []*pb.Sample{
					{FrameIds: []uint32{0}, Weight: 5},
				},
			},
		},
	}

	prof := CaptureToProfile(capture)
	if len(prof.Sample) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(prof.Sample))
	}
	if prof.Sample[0].Value[0] != 5 {
		t.Errorf("count = %d, want 5", prof.Sample[0].Value[0])
	}
	// 5 samples × 10ms = 50ms
	if prof.Sample[0].Value[1] != 50_000_000 {
		t.Errorf("cpu = %d, want 50000000", prof.Sample[0].Value[1])
	}
}
