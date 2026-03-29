// Package timeline builds rbscope Capture protos from raw BPF events.
//
// The Builder accumulates events from the collector's ring buffer, groups
// them per-thread, deduplicates strings and frames, computes cross-event
// references, and derives thread state intervals. The result is a
// [rbscopepb.Capture] that exporters can consume.
package timeline

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
	"github.com/schlubbi/rbscope/collector/pkg/symbols"
)

// Builder accumulates raw BPF events and produces a Capture proto.
type Builder struct {
	threads         map[uint32]*threadBuilder             // TID → builder
	threadNames     map[uint32]string                     // TID → name (cached at first sight)
	suspendedStacks map[uint32][]*collector.GVLStackEvent // TID → time-sorted SUSPENDED stacks
	strings         *stringTable
	frames          *frameTable

	startTime time.Time
	pid       uint32
	service   string
	hostname  string
	frequency uint32

	idleClassifier *IdleClassifier
	resolver       *symbols.Resolver // for native stack symbol resolution
}

// NewBuilder creates a Builder for a new capture window.
func NewBuilder(service, hostname string, pid, frequencyHz uint32) *Builder {
	st := newStringTable()
	return &Builder{
		threads:         make(map[uint32]*threadBuilder),
		threadNames:     make(map[uint32]string),
		suspendedStacks: make(map[uint32][]*collector.GVLStackEvent),
		strings:         st,
		frames:          newFrameTable(st),
		startTime:       time.Now(),
		pid:             pid,
		service:         service,
		hostname:        hostname,
		frequency:       frequencyHz,
		idleClassifier:  NewIdleClassifier(),
	}
}

// SetResolver sets the symbol resolver for native stack resolution.
// If set, native IPs from bpf_get_stack are resolved to function names
// and merged with Ruby frames.
func (b *Builder) SetResolver(r *symbols.Resolver) {
	b.resolver = r
}

// Ingest processes a decoded BPF event, routing it to the correct thread.
// Events from PIDs other than the target are silently dropped (handles
// Ingest processes a decoded BPF event, routing it to the correct thread.
// Events may come from forked children of the target PID (uprobe inheritance).
func (b *Builder) Ingest(event any) {
	switch ev := event.(type) {
	case *collector.RubySampleEvent:
		b.ensureThreadName(ev.TID, ev.PID)
		tb := b.thread(ev.TID)
		frames := collector.ParseInlineStack(ev.StackData)
		frameIDs := make([]uint32, 0, len(frames)+len(ev.NativeStackIPs))

		// Intern Ruby frames (leaf-first order)
		for _, f := range frames {
			frameIDs = append(frameIDs, b.frames.Intern(f.Label, f.Path, f.Line))
		}

		// Resolve and append native C frames from bpf_get_stack
		if len(ev.NativeStackIPs) > 0 && b.resolver != nil {
			nativeFrames := b.resolveNativeStack(ev.NativeStackIPs)
			frameIDs = append(frameIDs, nativeFrames...)
		}

		sample := &pb.Sample{
			TimestampNs: ev.Timestamp,
			FrameIds:    frameIDs,
			Weight:      ev.Weight,
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
		if ev.TCPStats != nil {
			ioEvent.TcpStats = &pb.TcpStats{
				SrttUs:        ev.TCPStats.SrttUs,
				SndCwnd:       ev.TCPStats.SndCwnd,
				TotalRetrans:  ev.TCPStats.TotalRetrans,
				PacketsOut:    ev.TCPStats.PacketsOut,
				RetransOut:    ev.TCPStats.RetransOut,
				LostOut:       ev.TCPStats.LostOut,
				RcvWnd:        ev.TCPStats.RcvWnd,
				BytesSent:     ev.TCPStats.BytesSent,
				BytesReceived: ev.TCPStats.BytesReceived,
			}
		}
		// Resolve native stack IPs from bpf_get_stack (syscall-time C stack)
		if len(ev.NativeStackIPs) > 0 && b.resolver != nil {
			ioEvent.NativeFrameIds = b.resolveNativeStack(ev.NativeStackIPs)
		}
		// Ruby context correlation deferred to Build() — GVL stack events
		// arrive from a different ring buffer and may not be present yet.
		tb.ioEvents = append(tb.ioEvents, ioEvent)
		tb.rawIOEvents = append(tb.rawIOEvents, ev)

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

	case *collector.GVLWaitEvent:
		tb := b.thread(ev.TID)
		gvlEvent := &pb.GVLEvent{
			TimestampNs:    ev.TimestampNs,
			WaitNs:         ev.WaitNs,
			HolderThreadId: 0, // Cross-thread correlation done in Build()
		}
		tb.gvlEvents = append(tb.gvlEvents, gvlEvent)

	case *collector.GVLStateChangeEvent:
		tb := b.thread(ev.TID)
		tb.gvlStateChanges = append(tb.gvlStateChanges, &pb.GVLStateChange{
			TimestampNs: ev.TimestampNs,
			State:       pb.GVLState(ev.GVLState),
		})

	case *collector.GVLStackEvent:
		// Store all Ruby stacks captured at GVL SUSPENDED for this TID.
		// They're correlated with I/O events by timestamp during Build().
		b.suspendedStacks[ev.TID] = append(b.suspendedStacks[ev.TID], ev)
	}
}

// parseAndInternSuspendedStack parses a serialized InlineStack (format v2)
// from a GVL SUSPENDED event and interns the frames into the capture's
// frame table. Returns frame IDs in leaf-first order (same as samples).
func (b *Builder) parseAndInternSuspendedStack(data []byte) []uint32 {
	frames := collector.ParseInlineStack(data)
	if len(frames) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(frames))
	for _, f := range frames {
		id := b.frames.Intern(f.Label, f.Path, f.Line)
		ids = append(ids, id)
	}
	return ids
}

// suspendedStackMaxGapNs is the maximum time gap between a GVL SUSPENDED
// stack and an I/O event for them to be considered from the same operation.
// This must be wide enough to cover the full I/O wait: SUSPENDED fires at
// GVL release (start of wait), while the io_tracer read/write fires at
// syscall completion (end of wait). For a 5ms database query, the gap is
// ~5ms; for a slow query or remote database, it could be 50-100ms.
// The isPlausibleIOContext check prevents false matches.
const suspendedStackMaxGapNs = 100_000_000 // 100ms

// findSuspendedStack finds the most recent GVL SUSPENDED stack that fired
// before the given timestamp. Uses binary search on the time-sorted list.
// Returns nil if no stack was captured before that time or if the nearest
// stack is too far away (> suspendedStackMaxGapNs).
func findSuspendedStack(stacks []*collector.GVLStackEvent, ioTimestampNs uint64) *collector.GVLStackEvent {
	if len(stacks) == 0 {
		return nil
	}
	// Binary search: find the rightmost stack with timestamp <= ioTimestampNs
	lo, hi := 0, len(stacks)-1
	result := -1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		if stacks[mid].TimestampNs <= ioTimestampNs {
			result = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if result < 0 {
		return nil
	}
	// Check temporal proximity — reject if too far from the I/O event.
	gap := ioTimestampNs - stacks[result].TimestampNs
	if gap > suspendedStackMaxGapNs {
		return nil
	}
	return stacks[result]
}

// correlateIOWithSuspendedStacks matches each I/O event on a thread to
// the Ruby stack captured at the most recent GVL SUSPENDED before the I/O.
// This produces unified Ruby + native C call trees in the profiler.
func (b *Builder) correlateIOWithSuspendedStacks(tid uint32, tb *threadBuilder) {
	stacks, ok := b.suspendedStacks[tid]
	if !ok || len(stacks) == 0 {
		return
	}

	// Sort stacks by timestamp (ring buffer may deliver slightly out of order)
	sort.Slice(stacks, func(i, j int) bool {
		return stacks[i].TimestampNs < stacks[j].TimestampNs
	})

	for _, ioEvent := range tb.ioEvents {
		ss := findSuspendedStack(stacks, ioEvent.TimestampNs)
		if ss == nil {
			continue
		}
		rubyFrameIDs := b.parseAndInternSuspendedStack(ss.StackData)
		if len(rubyFrameIDs) > 0 {
			ioEvent.RubyContextFrameIds = rubyFrameIDs
		}
	}
}

// resolveNativeStack resolves native instruction pointers from bpf_get_stack
// into frame table indices. Filters out:
//   - Ruby VM internals (libruby.so) — we have Ruby-level frames from the gem
//   - rbscope's own probe functions (__rbscope_probe_*)
//   - JIT anonymous regions ([anon:Ruby:rb_jit_reserve_addr_space])
//   - Empty/anonymous frames
//
// Keeps C extension frames (libtrilogy, pitchfork_http.so, etc.) and
// syscall entry points (read, write, etc. from libc).
//
// Native IPs from bpf_get_stack are in leaf-first order (innermost frame
// first), which matches our frame_ids convention.
func (b *Builder) resolveNativeStack(ips []uint64) []uint32 {
	var frameIDs []uint32
	for _, ip := range ips {
		funcName, libPath, isRubyVM := b.resolver.ResolveFunc(ip)
		if shouldFilterNativeFrame(funcName, libPath, isRubyVM) {
			continue
		}
		fid := b.frames.Intern(funcName, libPath, 0)
		frameIDs = append(frameIDs, fid)
	}
	return frameIDs
}

// shouldFilterNativeFrame returns true if a resolved native frame should
// be excluded from the profile output.
func shouldFilterNativeFrame(funcName, libPath string, isRubyVM bool) bool {
	// Ruby VM internals — we already have Ruby-level frames from the gem
	if isRubyVM {
		return true
	}
	// Empty/unresolved frames
	if funcName == "" {
		return true
	}
	// rbscope's own USDT probe functions
	if strings.HasPrefix(funcName, "__rbscope_probe_") {
		return true
	}
	// JIT-compiled Ruby code — anonymous memory regions from the JIT compiler.
	// These show as "[anon:Ruby:rb_jit_reserve_addr_space]+0x..." and are the
	// native representation of JIT'd Ruby methods. Filter for now; JIT frame
	// resolution is a future feature.
	if strings.Contains(libPath, "[anon:") || strings.Contains(funcName, "[anon:") {
		return true
	}
	// Process startup frames (ld-linux, _start) — noise at bottom of stack
	if funcName == "_start" || strings.HasPrefix(funcName, "_dl_") {
		return true
	}
	return false
}

// ioSampleMaxGapNs is the maximum time gap between an I/O event and a
// Ruby sample for them to be considered correlated. If the nearest Ruby
// sample is older than this, we skip synthesis (the Ruby context is stale).
const ioSampleMaxGapNs = 50_000_000 // 50ms

// synthesizeIOSamples creates synthetic flame graph samples from I/O events.
// Each I/O event that has a Ruby context (from GVL SUSPENDED correlation
// or nearest timer sample) AND native frames (from bpf_get_stack at syscall
// time) becomes a sample showing the unified call path:
//
//	PostsController#index → AR::exec_query → Trilogy#query   (Ruby context)
//	  → rb_trilogy_query → trilogy_query_send → write         (native I/O stack)
//
// This is rbscope's unique capability: no other Ruby profiler can show
// the full Ruby → C extension → syscall call path in a single flame chart.
//
// The Ruby context comes from the most recent GVL SUSPENDED stack or
// nearest timer sample. For accuracy, we reject contexts that are clearly
// from idle or unrelated I/O operations (e.g., SUSPENDED at IO#readpartial
// used for a Trilogy MySQL I/O event).
func (b *Builder) synthesizeIOSamples(tb *threadBuilder) {
	for _, ioEvent := range tb.ioEvents {
		// Need native frames to show something useful beyond what
		// regular timer samples already provide.
		if len(ioEvent.NativeFrameIds) == 0 {
			continue
		}

		// Get Ruby context: prefer SUSPENDED stack (captured at GVL
		// release, closest to the I/O), fall back to nearest timer sample.
		rubyFrameIDs := ioEvent.RubyContextFrameIds
		if len(rubyFrameIDs) > 0 && !b.isPlausibleIOContext(rubyFrameIDs, ioEvent.NativeFrameIds) {
			// SUSPENDED stack is from a different operation — discard it.
			rubyFrameIDs = nil
		}

		if len(rubyFrameIDs) == 0 {
			// Fallback: use the nearest timer sample's Ruby frames.
			sampleIdx := int(ioEvent.NearestSampleIdx)
			if sampleIdx < len(tb.samples) {
				sample := tb.samples[sampleIdx]
				// Check temporal proximity — skip if too far apart.
				var gap uint64
				if sample.TimestampNs > ioEvent.TimestampNs {
					gap = sample.TimestampNs - ioEvent.TimestampNs
				} else {
					gap = ioEvent.TimestampNs - sample.TimestampNs
				}
				if gap <= ioSampleMaxGapNs {
					candidate := extractRubyFrameIDs(sample.FrameIds, b.frames)
					if b.isPlausibleIOContext(candidate, ioEvent.NativeFrameIds) {
						rubyFrameIDs = candidate
					}
				}
			}
		}

		if len(rubyFrameIDs) == 0 {
			continue
		}

		// Build unified stack: Ruby frames (leaf-first) + native I/O frames (leaf-first).
		// The native frames from io_tracer are already leaf-first (syscall at [0]).
		//
		// In the flame graph this renders as:
		//   root: <main> → bundler → pitchfork → Rails → Controller → AR → Trilogy#query
		//   leaf: rb_trilogy_query → trilogy_query_send → write
		unified := make([]uint32, 0, len(rubyFrameIDs)+len(ioEvent.NativeFrameIds))
		unified = append(unified, ioEvent.NativeFrameIds...)
		unified = append(unified, rubyFrameIDs...)

		// Add as a synthetic sample with weight=1 (each I/O event
		// represents one occurrence, not a timed sample).
		tb.samples = append(tb.samples, &pb.Sample{
			TimestampNs: ioEvent.TimestampNs,
			FrameIds:    unified,
			Weight:      1,
			IsIoSample:  true,
		})
	}

	// Re-sort samples since we appended synthetic ones at the end.
	sort.Slice(tb.samples, func(i, j int) bool {
		return tb.samples[i].TimestampNs < tb.samples[j].TimestampNs
	})
}

// isPlausibleIOContext checks whether a Ruby stack is a plausible context
// for an I/O event. Rejects idle stacks and stacks where the leaf frame
// is a generic I/O cfunc that doesn't match the native call chain.
//
// For example, if the native stack is from Trilogy (rb_trilogy_query →
// trilogy_query_send → write), a Ruby context with Trilogy::Client#query
// is plausible. But a context with IO#readpartial (from HTTP parsing) is
// from a different I/O operation and should be rejected.
func (b *Builder) isPlausibleIOContext(rubyFrameIDs, nativeFrameIDs []uint32) bool {
	if len(rubyFrameIDs) == 0 {
		return false
	}

	// Check the leaf frame of the Ruby context.
	leafFID := rubyFrameIDs[0]
	if int(leafFID) >= len(b.frames.table) {
		return false
	}
	leaf := b.frames.table[leafFID]
	leafName := b.strings.Lookup(leaf.FunctionNameIdx)

	// Reject idle frames — these are from accept()/epoll_wait() loops
	if isIdleFrame(leafName) {
		return false
	}

	// Reject generic I/O cfuncs that are likely from a different operation.
	// These fire when Pitchfork does HTTP I/O, but the I/O event might be
	// from MySQL, file, or pipe I/O.
	if isGenericIOCfunc(leafName) {
		// Exception: if the native stack also has generic I/O (no C extension
		// frames), the generic Ruby cfunc IS the right context.
		if !hasExtensionFrames(nativeFrameIDs, b.frames) {
			return true // e.g., plain IO#write → write() from libc
		}
		return false
	}

	return true
}

// isIdleFrame returns true if the frame name indicates an idle/waiting state.
func isIdleFrame(name string) bool {
	return strings.Contains(name, "get_readers") ||
		strings.Contains(name, "IO.select") ||
		strings.Contains(name, "Kernel#sleep") ||
		strings.Contains(name, "Thread#join") ||
		strings.Contains(name, "ConditionVariable#wait")
}

// isGenericIOCfunc returns true if the frame is a generic Ruby I/O method
// that doesn't tell us which C extension is doing the I/O.
func isGenericIOCfunc(name string) bool {
	return name == "IO#readpartial" ||
		name == "IO#read" ||
		name == "IO#write" ||
		name == "IO#read_nonblock" ||
		name == "IO#write_nonblock" ||
		name == "IO#sysread" ||
		name == "IO#syswrite" ||
		name == "IO#close" ||
		name == "IO.select"
}

// hasExtensionFrames checks whether the native frame list contains frames
// from a C extension (not just libc/system libraries).
func hasExtensionFrames(nativeFrameIDs []uint32, ft *frameTable) bool {
	for _, fid := range nativeFrameIDs {
		if int(fid) >= len(ft.table) {
			continue
		}
		f := ft.table[fid]
		path := ft.strings.Lookup(f.FileNameIdx)
		// Skip libc, libpthread, ld-linux — system libraries
		if strings.Contains(path, "libc.so") ||
			strings.Contains(path, "libpthread") ||
			strings.Contains(path, "ld-linux") ||
			strings.Contains(path, "libm.so") {
			continue
		}
		// Any other .so is a C extension
		if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
			return true
		}
	}
	return false
}

// extractRubyFrameIDs returns only the Ruby-level frame IDs from a sample's
// frame_ids list, excluding any native frames that were appended by
// resolveNativeStack during ingestion.
func extractRubyFrameIDs(frameIDs []uint32, ft *frameTable) []uint32 {
	var ruby []uint32
	for _, fid := range frameIDs {
		if ft.IsNative(fid) {
			continue
		}
		ruby = append(ruby, fid)
	}
	return ruby
}

// SuspendedStackCounts returns per-TID counts of GVL SUSPENDED stack events.
func (b *Builder) SuspendedStackCounts() map[uint32]int {
	counts := make(map[uint32]int, len(b.suspendedStacks))
	for tid, stacks := range b.suspendedStacks {
		counts[tid] = len(stacks)
	}
	return counts
}

// SampleCounts returns per-TID counts of regular Ruby samples.
func (b *Builder) SampleCounts() map[uint32]int {
	counts := make(map[uint32]int, len(b.threads))
	for tid, tb := range b.threads {
		counts[tid] = len(tb.samples)
	}
	return counts
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
		sort.Slice(tb.gvlEvents, func(i, j int) bool {
			return tb.gvlEvents[i].TimestampNs < tb.gvlEvents[j].TimestampNs
		})

		// Cross-reference: IO → nearest sample
		crossRefIOToSamples(tb)

		// Correlate I/O events with GVL SUSPENDED Ruby stacks.
		// Both are now sorted by timestamp, so we can match each I/O
		// event to the most recent SUSPENDED stack on this TID.
		b.correlateIOWithSuspendedStacks(tid, tb)

		// Synthesize I/O samples for the flame graph. Each I/O event
		// with a Ruby context (from SUSPENDED stack or nearest sample)
		// and native frames becomes a sample showing the full call path:
		// Ruby code → C extension → syscall.
		b.synthesizeIOSamples(tb)

		// Cross-reference: IO ↔ sched (with idle classification)
		crossRefIOToSched(tb, b.idleClassifier)

		// Derive thread state intervals (with idle classification)
		states := deriveThreadStates(tb, b.idleClassifier)

		// Compute GVL state intervals from raw state changes
		captureEndNs := uint64(endTime.UnixNano())
		gvlIntervals := computeGVLIntervals(tb.gvlStateChanges, captureEndNs)

		tl := &pb.ThreadTimeline{
			ThreadId:        tid,
			ThreadNameIdx:   b.resolveThreadName(tid),
			Samples:         tb.samples,
			IoEvents:        tb.ioEvents,
			SchedEvents:     tb.schedEvents,
			GvlEvents:       tb.gvlEvents,
			SpanEvents:      tb.spanEvents,
			States:          states,
			GvlStateChanges: tb.gvlStateChanges,
			GvlIntervals:    gvlIntervals,
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
	b.threadNames = make(map[uint32]string)
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

// ensureThreadName caches a thread name from /proc. Called during Ingest
// while the thread is still alive. Tries both the target PID and the
// event's actual PID (for forked workers).
func (b *Builder) ensureThreadName(tid, eventPID uint32) {
	if _, ok := b.threadNames[tid]; ok {
		return
	}

	// Try as task of the target process
	for _, pid := range []uint32{b.pid, eventPID} {
		if pid == 0 {
			continue
		}
		path := fmt.Sprintf("/proc/%d/task/%d/comm", pid, tid)
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- path derived from PID, reads /proc
			if name := strings.TrimSpace(string(data)); name != "" {
				b.threadNames[tid] = name
				return
			}
		}
	}

	// Try as standalone process (main thread of forked worker)
	path := fmt.Sprintf("/proc/%d/comm", tid)
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- path derived from PID, reads /proc
		if name := strings.TrimSpace(string(data)); name != "" {
			b.threadNames[tid] = name
			return
		}
	}

	// Scan NSpid for namespace TIDs
	for _, pid := range []uint32{b.pid, eventPID} {
		if pid == 0 {
			continue
		}
		taskDir := fmt.Sprintf("/proc/%d/task", pid)
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			continue
		}
		tidStr := fmt.Sprintf("%d", tid)
		for _, e := range entries {
			statusPath := fmt.Sprintf("%s/%s/status", taskDir, e.Name())
			data, err := os.ReadFile(statusPath) // #nosec G304 -- path derived from PID, reads /proc
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(line, "NSpid:") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[len(fields)-1] == tidStr {
					commPath := fmt.Sprintf("%s/%s/comm", taskDir, e.Name())
					if commData, err := os.ReadFile(commPath); err == nil { // #nosec G304 -- path derived from PID, reads /proc
						if name := strings.TrimSpace(string(commData)); name != "" {
							b.threadNames[tid] = name
							return
						}
					}
				}
				break
			}
		}
	}
}

// resolveThreadName returns the interned string table index for a thread's name.
// Uses the name cached during Ingest(), falls back to "thread-<tid>".
func (b *Builder) resolveThreadName(tid uint32) uint32 {
	if name, ok := b.threadNames[tid]; ok {
		return b.strings.Intern(name)
	}
	return b.strings.Intern(fmt.Sprintf("thread-%d", tid))
}

type threadBuilder struct {
	samples         []*pb.Sample
	ioEvents        []*pb.IOEvent
	schedEvents     []*pb.SchedEvent
	gvlEvents       []*pb.GVLEvent
	gvlStateChanges []*pb.GVLStateChange
	spanEvents      []*pb.SpanEvent
	rawIOEvents     []*collector.IOEvent // kept for idle classification
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
