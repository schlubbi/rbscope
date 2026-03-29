package export

import (
	"testing"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

func TestCaptureToAllocProfile(t *testing.T) {
	capture := &pb.Capture{
		StringTable: []string{
			"",                                    // 0
			"PostsController#index",               // 1
			"app/controllers/posts_controller.rb", // 2
			"String",                              // 3
			"Array",                               // 4
		},
		FrameTable: []*pb.StackFrame{
			{FunctionNameIdx: 1, FileNameIdx: 2, LineNumber: 10}, // 0
		},
		Threads: []*pb.ThreadTimeline{
			{
				ThreadId: 1,
				Allocations: []*pb.AllocationSample{
					{
						TimestampNs:   1000000,
						ObjectTypeIdx: 3, // String
						SizeBytes:     40,
						FrameIds:      []uint32{0},
					},
					{
						TimestampNs:   2000000,
						ObjectTypeIdx: 4, // Array
						SizeBytes:     80,
						FrameIds:      []uint32{0},
					},
				},
			},
		},
	}

	prof := CaptureToAllocProfile(capture)
	if prof == nil {
		t.Fatal("CaptureToAllocProfile returned nil")
	}
	if len(prof.SampleType) != 2 {
		t.Errorf("expected 2 sample types, got %d", len(prof.SampleType))
	}
	if prof.SampleType[0].Type != "alloc_objects" {
		t.Errorf("expected alloc_objects, got %s", prof.SampleType[0].Type)
	}
	if prof.SampleType[1].Type != "alloc_space" {
		t.Errorf("expected alloc_space, got %s", prof.SampleType[1].Type)
	}
	if len(prof.Sample) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(prof.Sample))
	}
	// First sample: count=1, bytes=40
	if prof.Sample[0].Value[0] != 1 {
		t.Errorf("sample 0 count: got %d, want 1", prof.Sample[0].Value[0])
	}
	if prof.Sample[0].Value[1] != 40 {
		t.Errorf("sample 0 bytes: got %d, want 40", prof.Sample[0].Value[1])
	}
	// Second sample: count=1, bytes=80
	if prof.Sample[1].Value[1] != 80 {
		t.Errorf("sample 1 bytes: got %d, want 80", prof.Sample[1].Value[1])
	}
}

func TestCaptureToAllocProfile_Empty(t *testing.T) {
	capture := &pb.Capture{
		Threads: []*pb.ThreadTimeline{
			{ThreadId: 1, Samples: []*pb.Sample{{FrameIds: []uint32{0}, Weight: 1}}},
		},
	}
	prof := CaptureToAllocProfile(capture)
	if prof != nil {
		t.Error("expected nil for capture with no allocations")
	}
}
