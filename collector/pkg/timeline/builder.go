// Package timeline builds rbscope Capture protos from raw BPF events.
//
// The Builder accumulates events from the collector's ring buffer, groups
// them per-thread, deduplicates strings and frames, computes cross-event
// references, and derives thread state intervals. The result is a
// [rbscopepb.Capture] that exporters can consume.
package timeline

import (
	"sort"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// Builder accumulates raw BPF events and produces a Capture proto.
type Builder struct {
	threads map[uint32]*threadBuilder // TID → builder
	strings *stringTable
	frames  *frameTable

	startTime time.Time
	pid       uint32
	service   string
	hostname  string
	frequency uint32
}

// NewBuilder creates a Builder for a new capture window.
func NewBuilder(service, hostname string, pid, frequencyHz uint32) *Builder {
	st := newStringTable()
	return &Builder{
		threads:   make(map[uint32]*threadBuilder),
		strings:   st,
		frames:    newFrameTable(st),
		startTime: time.Now(),
		pid:       pid,
		service:   service,
		hostname:  hostname,
		frequency: frequencyHz,
	}
}

// Ingest processes a decoded BPF event, routing it to the correct thread.
func (b *Builder) Ingest(event any) {
	switch ev := event.(type) {
	case *collector.RubySampleEvent:
		tb := b.thread(ev.TID)
		frames := collector.ParseInlineStack(ev.StackData)
		frameIDs := make([]uint32, len(frames))
		for i, f := range frames {
			frameIDs[i] = b.frames.Intern(f.Label, f.Path, f.Line)
		}
		sample := &pb.Sample{
			TimestampNs: ev.Timestamp,
			FrameIds:    frameIDs,
			Weight:      1,
		}
		tb.samples = append(tb.samples, sample)

	case *collector.IOEvent:
		tb := b.thread(ev.TID)
		syscallName := collector.IoOpName(ev.Op)
		ioEvent := &pb.IOEvent{
			TimestampNs: ev.Timestamp,
			SyscallIdx:  b.strings.Intern(syscallName),
			Fd:          ev.FD,
			Bytes:       uint64(ev.Bytes), // #nosec G115 -- wire format
			LatencyNs:   ev.LatencyNs,
		}
		// Populate FD type and connection info from BPF enrichment
		if ev.FdType > 0 {
			ioEvent.FdType = pb.FdType(ev.FdType)
			fdInfo := ev.FormatFdInfo()
			if fdInfo != "" {
				ioEvent.FdInfoIdx = b.strings.Intern(fdInfo)
			}
			ioEvent.LocalPort = uint32(ev.LocalPort)
			ioEvent.RemotePort = uint32(ev.RemotePort)
		}
		// Populate TCP stats
		if ev.TcpStats != nil {
			ioEvent.TcpStats = &pb.TcpStats{
				SrttUs:        ev.TcpStats.SrttUs,
				SndCwnd:       ev.TcpStats.SndCwnd,
				TotalRetrans:  ev.TcpStats.TotalRetrans,
				PacketsOut:    ev.TcpStats.PacketsOut,
				RetransOut:    ev.TcpStats.RetransOut,
				LostOut:       ev.TcpStats.LostOut,
				RcvWnd:        ev.TcpStats.RcvWnd,
				BytesSent:     ev.TcpStats.BytesSent,
				BytesReceived: ev.TcpStats.BytesReceived,
			}
		}
		tb.ioEvents = append(tb.ioEvents, ioEvent)

	case *collector.SchedEvent:
		tb := b.thread(ev.TID)
		schedEvent := &pb.SchedEvent{
			TimestampNs: ev.Timestamp,
			OffCpuNs:    ev.OffCPUNs,
		}
		tb.schedEvents = append(tb.schedEvents, schedEvent)

	case *collector.RubySpanEvent:
		// Span events will be correlated in a future pass.
		// For now, just record the raw event.
		tb := b.thread(ev.TID)
		_ = tb // placeholder for span correlation
	}
}

// Build produces the final Capture with cross-references and thread states.
func (b *Builder) Build() *pb.Capture {
	endTime := time.Now()

	// Build per-thread timelines
	threads := make([]*pb.ThreadTimeline, 0, len(b.threads))
	for tid, tb := range b.threads {
		// Sort events by timestamp within each thread
		sort.Slice(tb.samples, func(i, j int) bool {
			return tb.samples[i].TimestampNs < tb.samples[j].TimestampNs
		})
		sort.Slice(tb.ioEvents, func(i, j int) bool {
			return tb.ioEvents[i].TimestampNs < tb.ioEvents[j].TimestampNs
		})
		sort.Slice(tb.schedEvents, func(i, j int) bool {
			return tb.schedEvents[i].TimestampNs < tb.schedEvents[j].TimestampNs
		})

		// Cross-reference: IO → nearest sample
		crossRefIOToSamples(tb)

		// Cross-reference: IO ↔ sched
		crossRefIOToSched(tb)

		// Derive thread state intervals
		states := deriveThreadStates(tb)

		tl := &pb.ThreadTimeline{
			ThreadId:    tid,
			Samples:     tb.samples,
			IoEvents:    tb.ioEvents,
			SchedEvents: tb.schedEvents,
			SpanEvents:  tb.spanEvents,
			States:      states,
		}
		threads = append(threads, tl)
	}

	// Sort threads by TID for deterministic output
	sort.Slice(threads, func(i, j int) bool {
		return threads[i].ThreadId < threads[j].ThreadId
	})

	capture := &pb.Capture{
		Header: &pb.CaptureHeader{
			Version:           2,
			ServiceName:       b.service,
			Hostname:          b.hostname,
			Pid:               b.pid,
			StartTimeNs:       uint64(b.startTime.UnixNano()),
			EndTimeNs:         uint64(endTime.UnixNano()),
			SampleFrequencyHz: b.frequency,
		},
		StringTable: b.strings.Table(),
		FrameTable:  b.frames.Table(),
		Threads:     threads,
		Categories:  defaultCategories(),
	}

	return capture
}

// Reset clears the builder for the next capture window.
func (b *Builder) Reset() {
	b.threads = make(map[uint32]*threadBuilder)
	b.strings = newStringTable()
	b.frames = newFrameTable(b.strings)
	b.startTime = time.Now()
}

func (b *Builder) thread(tid uint32) *threadBuilder {
	tb, ok := b.threads[tid]
	if !ok {
		tb = &threadBuilder{}
		b.threads[tid] = tb
	}
	return tb
}

type threadBuilder struct {
	samples     []*pb.Sample
	ioEvents    []*pb.IOEvent
	schedEvents []*pb.SchedEvent
	spanEvents  []*pb.SpanEvent
}

func defaultCategories() []*pb.Category {
	return []*pb.Category{
		{Id: 0, Name: "Other", Color: "grey"},
		{Id: 1, Name: "CPU", Color: "blue"},
		{Id: 2, Name: "I/O", Color: "orange"},
		{Id: 3, Name: "GVL", Color: "red"},
		{Id: 4, Name: "GC", Color: "purple"},
		{Id: 5, Name: "Idle", Color: "transparent"},
	}
}

