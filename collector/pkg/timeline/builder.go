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
	"github.com/schlubbi/rbscope/collector/pkg/offsets"
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
	resolver       *symbols.Resolver      // for native stack symbol resolution
	frameResolver  *offsets.FrameResolver // for BPF stack walker iseq resolution

	// hostToContainerPID maps host PIDs (from BPF events) back to container
	// PIDs (visible in /proc) for PID-namespace environments.
	hostToContainerPID map[uint32]uint32

	// pidDiscoverer, when set, maps a host PID (from BPF events) to its
	// container PID (visible in /proc). Used to discover PID namespace
	// mappings for dynamically forked workers. The function is provided
	// by the caller (e.g., bpf.DiscoverHostPID reversed).
	pidDiscoverer func(hostPID uint32) (containerPID uint32, ok bool)

	allocResolveLogCount int                 // throttle diagnostic log messages
	seenPIDs             map[uint32]struct{} // PIDs we've eagerly opened mem for
	nativeAll            bool                // include Ruby VM native frames
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
		seenPIDs:        make(map[uint32]struct{}),
	}
}

// SetResolver sets the symbol resolver for native stack resolution.
// If set, native IPs from bpf_get_stack are resolved to function names
// and merged with Ruby frames.
func (b *Builder) SetResolver(r *symbols.Resolver) {
	b.resolver = r
}

// SetFrameResolver sets the BPF stack walker frame resolver for iseq → method/path resolution.
func (b *Builder) SetFrameResolver(r *offsets.FrameResolver) {
	b.frameResolver = r
}

// CloseFrameResolver releases cached /proc/pid/mem file handles.
func (b *Builder) CloseFrameResolver() {
	if b.frameResolver != nil {
		b.frameResolver.Close()
	}
}

// SetPIDDiscoverer registers a function that resolves host PIDs to container
// PIDs for dynamically forked workers. Called lazily when a new PID is seen.
func (b *Builder) SetPIDDiscoverer(fn func(hostPID uint32) (containerPID uint32, ok bool)) {
	b.pidDiscoverer = fn
}

// SetNativeAll controls whether Ruby VM native frames (libruby internals)
// are included in the profile. When true, frames from libruby.so and the
// ruby binary are shown alongside C extension frames.
func (b *Builder) SetNativeAll(v bool) {
	b.nativeAll = v
}

// discoverPIDMapping checks if the given PID needs host→container mapping.
// If /proc/<pid> doesn't exist and a pidDiscoverer is set, it tries to
// find the container PID by scanning /proc for sibling processes.
func (b *Builder) discoverPIDMapping(hostPID uint32) {
	if _, ok := b.hostToContainerPID[hostPID]; ok {
		return // already mapped
	}
	// Check if /proc/<hostPID> exists — if so, no mapping needed
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", hostPID)); err == nil {
		return
	}
	// PID doesn't exist in our namespace — try the discoverer
	if b.pidDiscoverer != nil {
		if containerPID, ok := b.pidDiscoverer(hostPID); ok {
			b.SetHostToContainerPID(hostPID, containerPID)
			fmt.Fprintf(os.Stderr, "rbscope: discovered PID mapping: host %d → container %d\n", hostPID, containerPID)
		}
	}
}

// SetHostToContainerPID registers a host→container PID mapping so the
// frame resolver reads /proc/<containerPID>/mem instead of the host PID
// that BPF events carry. Required when running inside a PID namespace.
func (b *Builder) SetHostToContainerPID(hostPID, containerPID uint32) {
	if b.hostToContainerPID == nil {
		b.hostToContainerPID = make(map[uint32]uint32)
	}
	b.hostToContainerPID[hostPID] = containerPID
}

// Ingest processes a decoded BPF event, routing it to the correct thread.
// Events from PIDs other than the target are silently dropped (handles
// Ingest processes a decoded BPF event, routing it to the correct thread.
// Events may come from forked children of the target PID (uprobe inheritance).
func (b *Builder) Ingest(event any) {
	switch ev := event.(type) {
	case *collector.RubyAllocEvent:
		b.ensureThreadName(ev.TID, ev.PID)
		tb := b.thread(ev.TID)

		// Eagerly open /proc/pid/mem on first sight of a new PID.
		// The cached fd keeps the address space alive even after worker death.
		if _, seen := b.seenPIDs[ev.PID]; !seen && b.frameResolver != nil {
			b.seenPIDs[ev.PID] = struct{}{}
			// For PID namespace environments: discover the container PID
			// for this host PID so /proc access works.
			b.discoverPIDMapping(ev.PID)
			// Open mem with the (possibly mapped) PID
			pid := ev.PID
			if mapped, ok := b.hostToContainerPID[ev.PID]; ok {
				pid = mapped
			}
			b.frameResolver.EagerOpenMem(pid)
		}

		var frameIDs []uint32

		// Try format v3 (raw frame addresses) first, fall back to v2 (inline strings).
		rawFrames := collector.ParseRawFrameStack(ev.StackData)
		if rawFrames != nil && b.frameResolver != nil {
			// Format v3: resolve raw VALUE pointers via /proc/pid/mem.
			// This is the low-overhead path — the gem sent raw rb_profile_frames
			// VALUEs instead of resolved strings.
			procPID := ev.PID
			if mapped, ok := b.hostToContainerPID[ev.PID]; ok {
				procPID = mapped
			}
			frameIDs = make([]uint32, 0, len(rawFrames))
			for i, rf := range rawFrames {
				info := b.frameResolver.ResolveProfileFrame(procPID, rf.Value, rf.Line)
				if info.Label == "" {
					if b.allocResolveLogCount < 5 {
						b.allocResolveLogCount++
						fmt.Fprintf(os.Stderr, "rbscope: alloc frame resolve failed: pid=%d frame[%d] value=0x%x line=%d (total frames=%d)\n",
							procPID, i, rf.Value, rf.Line, len(rawFrames))
					}
					continue // skip unresolvable frames
				}
				path := shortenRubyPath(info.Path)
				frameIDs = append(frameIDs, b.frames.Intern(info.Label, path, info.Line))
			}
		} else if rawFrames == nil && len(ev.StackData) > 0 {
			if b.allocResolveLogCount < 3 {
				b.allocResolveLogCount++
				fmt.Fprintf(os.Stderr, "rbscope: alloc stack not v3: first byte=%d len=%d resolver=%v\n",
					ev.StackData[0], len(ev.StackData), b.frameResolver != nil)
			}
			// Format v2 fallback: inline strings already resolved by the gem.
			frames := collector.ParseInlineStack(ev.StackData)
			frameIDs = make([]uint32, 0, len(frames))
			for _, f := range frames {
				frameIDs = append(frameIDs, b.frames.Intern(f.Label, f.Path, f.Line))
			}
		}

		alloc := &pb.AllocationSample{
			TimestampNs:   ev.Timestamp,
			ObjectTypeIdx: b.strings.Intern(ev.ObjectType),
			SizeBytes:     ev.SizeBytes,
			FrameIds:      frameIDs,
		}
		tb.allocations = append(tb.allocations, alloc)

	case *collector.RubySampleEvent:
		b.ensureThreadName(ev.TID, ev.PID)
		if _, seen := b.seenPIDs[ev.PID]; !seen && b.frameResolver != nil {
			b.seenPIDs[ev.PID] = struct{}{}
			b.discoverPIDMapping(ev.PID)
			pid := ev.PID
			if mapped, ok := b.hostToContainerPID[ev.PID]; ok {
				pid = mapped
			}
			b.frameResolver.EagerOpenMem(pid)
		}
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
			Reason:      prevStateToReason(ev.PrevState),
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
		b.ensureThreadName(ev.TID, ev.PID)
		tb := b.thread(ev.TID)
		tb.gvlStateChanges = append(tb.gvlStateChanges, &pb.GVLStateChange{
			TimestampNs: ev.TimestampNs,
			State:       pb.GVLState(ev.GVLState),
		})

	case *collector.GVLStackEvent:
		b.ensureThreadName(ev.TID, ev.PID)
		// Store all Ruby stacks captured at GVL SUSPENDED for this TID.
		// They're correlated with I/O events by timestamp during Build().
		b.suspendedStacks[ev.TID] = append(b.suspendedStacks[ev.TID], ev)

	case *collector.StackWalkEvent:
		b.ensureThreadName(ev.TID, ev.PID)
		if _, seen := b.seenPIDs[ev.PID]; !seen && b.frameResolver != nil {
			b.seenPIDs[ev.PID] = struct{}{}
			b.discoverPIDMapping(ev.PID)
			pid := ev.PID
			if mapped, ok := b.hostToContainerPID[ev.PID]; ok {
				pid = mapped
			}
			b.frameResolver.EagerOpenMem(pid)
		}
		// BPF stack walker event — resolve iseq addresses to method/path/line.
		if b.frameResolver == nil {
			break
		}
		// In PID namespaces, BPF events carry host PIDs but /proc uses
		// container PIDs. Translate for all /proc/pid/mem reads.
		procPID := ev.PID
		if mapped, ok := b.hostToContainerPID[ev.PID]; ok {
			procPID = mapped
		}
		b.ensureThreadName(ev.TID, ev.PID)
		tb := b.thread(ev.TID)

		type resolvedFrame struct {
			id       uint32
			resolved bool // true if we got a real label (not [unknown]/[cfunc]-only)
		}
		resolved := make([]resolvedFrame, 0, len(ev.Frames))
		for _, frame := range ev.Frames {
			if frame.IsCfunc || frame.IseqAddr == 0 {
				// For cfunc frames, PC carries EP (set by BPF walker).
				// Resolve method name via ep[-2] → method entry → called_id.
				cfuncName := ""
				className := ""
				if b.frameResolver != nil {
					cfuncName = b.frameResolver.ResolveCfuncName(procPID, frame.PC)
					className = b.frameResolver.ResolveClassName(procPID, frame.SelfVal)
				}
				label := "[cfunc]"
				ok := false
				if className != "" && cfuncName != "" {
					label = className + "#" + cfuncName
					ok = true
				} else if className != "" {
					label = className + " [cfunc]"
					ok = true
				} else if cfuncName != "" {
					label = cfuncName + " [cfunc]"
					ok = true
				}
				resolved = append(resolved, resolvedFrame{b.frames.Intern(label, "", 0), ok})
				continue
			}
			info, err := b.frameResolver.Resolve(procPID, frame.IseqAddr)
			if err != nil {
				resolved = append(resolved, resolvedFrame{b.frames.Intern("[unknown]", "", 0), false})
				continue
			}
			label := info.Label
			if label == "" {
				label = "[unknown]"
			}
			path := shortenRubyPath(info.Path)

			// Resolve class name from cfp->self for qualified method names.
			// e.g. "call" → "Rack::Logger#call"
			className := b.frameResolver.ResolveClassName(procPID, frame.SelfVal)
			if className != "" {
				label = className + "#" + label
			} else if ambiguousNames[label] && path != "" {
				// Fallback: qualify with file context if no class name
				label = label + " [" + pathStem(path) + "]"
			}

			resolved = append(resolved, resolvedFrame{b.frames.Intern(label, path, info.Line), true})
		}

		// Trim trailing unresolved frames — the BPF walker can overshoot
		// end_cfp by a few slots, producing garbage frames at the stack bottom.
		for len(resolved) > 0 && !resolved[len(resolved)-1].resolved {
			resolved = resolved[:len(resolved)-1]
		}

		frameIDs := make([]uint32, len(resolved))
		for i, rf := range resolved {
			frameIDs[i] = rf.id
		}

		// Resolve native stack IPs
		if len(ev.NativeStackIPs) > 0 && b.resolver != nil {
			nativeFrames := b.resolveNativeStack(ev.NativeStackIPs)
			frameIDs = append(frameIDs, nativeFrames...)
		}

		sample := &pb.Sample{
			TimestampNs: ev.Timestamp,
			FrameIds:    frameIDs,
			Weight:      1,
		}
		tb.samples = append(tb.samples, sample)
	}
}

// ambiguousNames is the set of Ruby method names that appear across many
// different classes/modules, making them indistinguishable in a flame graph
// without file context. Generated from Rails middleware stacks where
// every layer has a `call` method.
var ambiguousNames = map[string]bool{
	"call":             true,
	"new":              true,
	"initialize":       true,
	"each":             true,
	"map":              true,
	"select":           true,
	"block in call":    true,
	"block in new":     true,
	"block in each":    true,
	"block (2 levels)": true,
	"block (3 levels)": true,
}

// qualifyMethodName adds a short file context to ambiguous method names
// so they're distinguishable in a flame graph. Only applied in BPF mode.
//
//	"call" + "rack/logger.rb"  → "call [rack/logger]"
//	"index" + "posts_controller.rb" → "index" (not ambiguous, left as-is)
func qualifyMethodName(name, path string) string {
	if path == "" || !ambiguousNames[name] {
		return name
	}
	stem := pathStem(path)
	if stem == "" {
		return name
	}
	return name + " [" + stem + "]"
}

// pathStem returns a short, readable identifier from a file path.
// Uses up to 2 path components without the extension:
//
//	"rack/logger.rb" → "rack/logger"
//	"rails/rack/logger.rb" → "rack/logger"
//	"posts_controller.rb" → "posts_controller"
func pathStem(path string) string {
	// Strip extension
	if i := strings.LastIndex(path, "."); i > 0 {
		path = path[:i]
	}
	// Take up to last 2 components
	parts := strings.Split(path, "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

// shortenRubyPath strips common prefixes from Ruby file paths for readability.
// Transforms vendor/bundle gem paths and ruby stdlib paths into short forms:
//
//	".../vendor/bundle/ruby/4.0.0/gems/rack-3.2.5/lib/rack/logger.rb"
//	 → "rack/logger.rb"
//
//	".../lib/ruby/4.0.0/net/http.rb"  → "net/http.rb"
//	"/app/controllers/posts_controller.rb" → "app/controllers/posts_controller.rb"
func shortenRubyPath(path string) string {
	if path == "" {
		return path
	}

	// Gem paths: .../gems/<gem-name>/lib/<rest>  → <rest>
	if i := strings.Index(path, "/gems/"); i >= 0 {
		after := path[i+6:] // after "/gems/"
		// Skip gem name+version: "rack-3.2.5/lib/rack/logger.rb" → "rack/logger.rb"
		if j := strings.Index(after, "/lib/"); j >= 0 {
			return after[j+5:]
		}
		// No /lib/ — just skip gem name: "bundler-4.0.9/exe/bundle" → "exe/bundle"
		if j := strings.Index(after, "/"); j >= 0 {
			return after[j+1:]
		}
	}

	// Ruby stdlib: .../lib/ruby/<version>/<rest> → <rest>
	if i := strings.Index(path, "/lib/ruby/"); i >= 0 {
		after := path[i+10:] // after "/lib/ruby/"
		// Skip version: "4.0.0/net/http.rb" → "net/http.rb"
		if j := strings.Index(after, "/"); j >= 0 {
			return after[j+1:]
		}
	}

	// App paths: keep from /app/ onward
	if i := strings.Index(path, "/app/"); i >= 0 {
		return path[i+1:]
	}

	// Config paths: keep from /config/ onward
	if i := strings.Index(path, "/config/"); i >= 0 {
		return path[i+1:]
	}

	// Fallback: strip any leading path up to and including /lib/
	if i := strings.LastIndex(path, "/lib/"); i >= 0 {
		return path[i+5:]
	}

	return path
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
	if result < 0 || result >= len(stacks) {
		return nil
	}
	s := stacks[result] // #nosec G602 -- result bounds checked above
	// Check temporal proximity — reject if too far from the I/O event.
	gap := ioTimestampNs - s.TimestampNs
	if gap > suspendedStackMaxGapNs {
		return nil
	}
	return s
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
		if shouldFilterNativeFrame(funcName, libPath, isRubyVM, b.nativeAll) {
			continue
		}
		fid := b.frames.Intern(funcName, libPath, 0)
		frameIDs = append(frameIDs, fid)
	}
	return frameIDs
}

// shouldFilterNativeFrame returns true if a resolved native frame should
// be excluded from the profile output.
func shouldFilterNativeFrame(funcName, libPath string, isRubyVM, nativeAll bool) bool {
	// Ruby VM internals — filtered by default, kept with --native-all
	if isRubyVM && !nativeAll {
		return true
	}
	// Empty/unresolved frames
	if funcName == "" {
		return true
	}
	// Unresolved raw addresses (no mapping found) — these appear as "0x..."
	// and create noise at the stack root.
	if strings.HasPrefix(funcName, "0x") {
		return true
	}
	// Library+offset unresolved frames — partially resolved (library name known
	// but symbol unknown). Appear as "libname+0xNNNN" or "/path/to/lib.so+0xNNNN".
	if strings.Contains(funcName, "+0x") {
		return true
	}
	// rbscope's own USDT probe functions and Rust internals
	if strings.HasPrefix(funcName, "__rbscope_probe_") {
		return true
	}
	if strings.Contains(libPath, "rbscope.so") {
		return true
	}
	// uprobe trampolines — BPF infrastructure, not application code
	if strings.HasPrefix(funcName, "[uprobes]") || strings.Contains(libPath, "[uprobes]") {
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
	// C runtime and allocator internals below the Ruby entry point
	if funcName == "free" || funcName == "malloc" || funcName == "calloc" || funcName == "realloc" {
		return true
	}
	if funcName == "clock_gettime" || funcName == "__clock_gettime" {
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

// prevStateToReason maps the Linux task prev_state from sched_switch to an
// OffCPUReason. This provides a baseline classification that crossRefIOToSched
// may override with OFF_CPU_IO_BLOCKED when a matching IO event is found.
func prevStateToReason(prevState uint8) pb.OffCPUReason {
	// Linux task_state bits:
	//   0 = TASK_RUNNING (preempted by scheduler)
	//   1 = TASK_INTERRUPTIBLE (voluntary sleep — waiting for event)
	//   2 = TASK_UNINTERRUPTIBLE (D-state — kernel I/O)
	switch prevState {
	case 0:
		return pb.OffCPUReason_OFF_CPU_PREEMPTED
	case 1:
		return pb.OffCPUReason_OFF_CPU_VOLUNTARY_SLEEP
	case 2:
		return pb.OffCPUReason_OFF_CPU_IO_BLOCKED // D-state — kernel disk I/O
	default:
		return pb.OffCPUReason_OFF_CPU_UNKNOWN
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
			Allocations:     tb.allocations,
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
	allocations     []*pb.AllocationSample
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
