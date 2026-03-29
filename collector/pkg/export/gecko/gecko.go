// Package gecko converts rbscope Capture protos into Firefox Profiler
// (Gecko) JSON format. The output can be loaded directly into
// https://profiler.firefox.com for interactive timeline analysis.
//
// Uses the Gecko raw profile format (meta.version=29) which the profiler
// processes on load. Each thread has its own stringTable, frameTable,
// and stackTable.
package gecko

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// --- Top-level structures ---

// Profile is the top-level Gecko profile JSON.
type Profile struct {
	Meta         Meta      `json:"meta"`
	Libs         []any     `json:"libs"`
	Threads      []Thread  `json:"threads"`
	Processes    []any     `json:"processes"`
	PausedRanges []any     `json:"pausedRanges"`
	Counters     []Counter `json:"counters,omitempty"`
}

// Meta contains profile metadata.
type Meta struct {
	Version      int            `json:"version"`
	Interval     float64        `json:"interval"`
	StartTime    float64        `json:"startTime"`
	ShutdownTime any            `json:"shutdownTime"` // null
	Categories   []Category     `json:"categories"`
	MarkerSchema []MarkerSchema `json:"markerSchema"`
	Stackwalk    int            `json:"stackwalk"`
	Debug        int            `json:"debug"`
	GCPoison     int            `json:"gcpoison"`
	AsyncStack   int            `json:"asyncstack"`
	ProcessType  int            `json:"processType"`
	Platform     string         `json:"platform"`
	Product      string         `json:"product"`
	Oscpu        string         `json:"oscpu,omitempty"`
	SampleUnits  *SampleUnits   `json:"sampleUnits,omitempty"`
}

// SampleUnits defines units for time fields.
type SampleUnits struct {
	Time           string `json:"time"`
	EventDelay     string `json:"eventDelay"`
	ThreadCPUDelta string `json:"threadCPUDelta"`
}

// Category defines a profiler category with color.
type Category struct {
	Name          string   `json:"name"`
	Color         string   `json:"color"`
	Subcategories []string `json:"subcategories"`
}

// --- Thread ---

// Thread represents a profiled thread (Gecko raw format).
type Thread struct {
	Name           string         `json:"name"`
	RegisterTime   float64        `json:"registerTime"`
	ProcessType    string         `json:"processType"`
	UnregisterTime any            `json:"unregisterTime"` // null
	TID            int            `json:"tid"`
	PID            int            `json:"pid"`
	Markers        MarkersTable   `json:"markers"`
	Samples        SamplesTable   `json:"samples"`
	FrameTable     FrameTableData `json:"frameTable"`
	StackTable     StackTableData `json:"stackTable"`
	StringTable    []string       `json:"stringTable"`
}

// SamplesTable uses schema + tuple data format.
type SamplesTable struct {
	Schema SampleTupleSchema `json:"schema"`
	Data   [][]any           `json:"data"`
}

// SampleTupleSchema defines tuple positions.
type SampleTupleSchema struct {
	Stack          int `json:"stack"`
	Time           int `json:"time"`
	EventDelay     int `json:"eventDelay"`
	ThreadCPUDelta int `json:"threadCPUDelta,omitempty"`
}

// MarkersTable uses schema + tuple data format.
type MarkersTable struct {
	Schema MarkerTupleSchema `json:"schema"`
	Data   [][]any           `json:"data"`
}

// MarkerTupleSchema defines tuple positions.
type MarkerTupleSchema struct {
	Name      int `json:"name"`
	StartTime int `json:"startTime"`
	EndTime   int `json:"endTime"`
	Phase     int `json:"phase"`
	Category  int `json:"category"`
	Data      int `json:"data"`
}

// FrameTableData uses schema + tuple data format.
type FrameTableData struct {
	Schema FrameTupleSchema `json:"schema"`
	Data   [][]any          `json:"data"`
}

// FrameTupleSchema defines tuple positions.
type FrameTupleSchema struct {
	Location       int `json:"location"`
	RelevantForJS  int `json:"relevantForJS"`
	InnerWindowID  int `json:"innerWindowID"`
	Implementation int `json:"implementation"`
	Line           int `json:"line"`
	Column         int `json:"column"`
	Category       int `json:"category"`
	Subcategory    int `json:"subcategory"`
}

// StackTableData uses schema + tuple data format.
type StackTableData struct {
	Schema StackTupleSchema `json:"schema"`
	Data   [][]any          `json:"data"`
}

// StackTupleSchema defines tuple positions.
type StackTupleSchema struct {
	Prefix int `json:"prefix"`
	Frame  int `json:"frame"`
}

// --- Marker Schema ---

// MarkerSchema defines a custom marker type.
type MarkerSchema struct {
	Name         string        `json:"name"`
	Display      []string      `json:"display"`
	ChartLabel   string        `json:"chartLabel,omitempty"`
	TooltipLabel string        `json:"tooltipLabel,omitempty"`
	TableLabel   string        `json:"tableLabel,omitempty"`
	Data         []SchemaField `json:"data"`
}

// SchemaField defines a data field in a marker schema.
type SchemaField struct {
	Key        string `json:"key"`
	Label      string `json:"label,omitempty"`
	Format     string `json:"format"`
	Searchable *bool  `json:"searchable,omitempty"`
}

// --- Counter ---

// Counter is a time-series counter track.
type Counter struct {
	Name        string         `json:"name"`
	Category    string         `json:"category"`
	Description string         `json:"description"`
	Samples     CounterSamples `json:"samples"`
}

// CounterSamples holds counter data in schema + tuple format.
type CounterSamples struct {
	Schema CounterSchema `json:"schema"`
	Data   [][]any       `json:"data"`
}

// CounterSchema defines tuple positions.
type CounterSchema struct {
	Time   int `json:"time"`
	Count  int `json:"count"`
	Number int `json:"number"`
}

// MarkerPhase constants define timing semantics for markers.
const (
	MarkerPhaseInstant  = 0
	MarkerPhaseInterval = 1
)

// --- Category indices (must match defaultCategories order) ---

const (
	catOther  = 0
	catApp    = 1  // User application code — green
	catRails  = 2  // Rails framework — red
	catGem    = 3  // Third-party gems — lightblue
	catRuby   = 4  // Ruby stdlib / core — purple
	catCfunc  = 5  // C extension functions — yellow
	catNative = 6  // Native C library code (.so/.dylib) — blue
	catIO     = 7  // I/O markers — orange
	catGVL    = 8  // GVL contention — magenta
	catGC     = 9  // Garbage collection — brown
	catOTel   = 10 // OTel spans — purple
	catIdle   = 11 // Idle/waiting — grey
)

// Export converts a Capture proto to Gecko JSON and writes it to path.
// If the path ends in .gz, the output is gzip-compressed. Firefox
// Profiler accepts both plain JSON and gzipped JSON.
func Export(capture *pb.Capture, path string) error {
	profile := Build(capture)

	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return fmt.Errorf("create gecko profile: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var w io.Writer = f
	if strings.HasSuffix(path, ".gz") {
		gw := gzip.NewWriter(f)
		defer gw.Close() //nolint:errcheck
		w = gw
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(profile); err != nil {
		return fmt.Errorf("encode gecko profile: %w", err)
	}
	return nil
}

// Build converts a Capture proto to a Gecko Profile struct.
func Build(capture *pb.Capture) *Profile {
	categories := defaultCategories()
	threads := make([]Thread, 0, len(capture.Threads))

	startTimeMs := float64(capture.Header.StartTimeNs) / 1e6
	intervalMs := 1000.0 / float64(capture.Header.SampleFrequencyHz)
	if intervalMs <= 0 {
		intervalMs = 10.0
	}

	for _, tl := range capture.Threads {
		threads = append(threads, buildThread(capture, tl, startTimeMs))
	}

	return &Profile{
		Meta: Meta{
			Version:      33,
			Interval:     intervalMs,
			StartTime:    startTimeMs,
			ShutdownTime: nil,
			Categories:   categories,
			MarkerSchema: defaultMarkerSchemas(),
			Stackwalk:    0,
			Debug:        0,
			GCPoison:     0,
			AsyncStack:   0,
			ProcessType:  0,
			Platform:     "Linux",
			Product:      fmt.Sprintf("rbscope — %s", capture.Header.ServiceName),
			SampleUnits:  &SampleUnits{Time: "ms", EventDelay: "ms", ThreadCPUDelta: "µs"},
		},
		Libs:         []any{},
		Threads:      threads,
		Processes:    []any{},
		PausedRanges: []any{},
	}
}

// --- Per-thread builder ---

// threadBuilder accumulates per-thread string, frame, and stack tables.
type threadBuilder struct {
	capture     *pb.Capture
	startTimeMs float64
	strings     []string
	stringIdx   map[string]int
	frameData   [][]any
	frameKeys   map[string]int
	stackData   [][]any
	stackKeys   map[string]int
}

func newThreadBuilder(capture *pb.Capture, startTimeMs float64) *threadBuilder {
	return &threadBuilder{
		capture:     capture,
		startTimeMs: startTimeMs,
		strings:     []string{},
		stringIdx:   make(map[string]int),
		frameData:   [][]any{},
		frameKeys:   make(map[string]int),
		stackData:   [][]any{},
		stackKeys:   make(map[string]int),
	}
}

func (tb *threadBuilder) internString(s string) int {
	if idx, ok := tb.stringIdx[s]; ok {
		return idx
	}
	idx := len(tb.strings)
	tb.strings = append(tb.strings, s)
	tb.stringIdx[s] = idx
	return idx
}

// internFrame creates a frame table entry and returns its index.
// Frame tuple: [location, relevantForJS, innerWindowID, implementation, line, column, category, subcategory]
func (tb *threadBuilder) internFrame(rbFrameIdx uint32) int {
	ft := tb.capture.FrameTable
	if int(rbFrameIdx) >= len(ft) {
		label := "(unknown)"
		key := label
		if idx, ok := tb.frameKeys[key]; ok {
			return idx
		}
		locIdx := tb.internString(label)
		idx := len(tb.frameData)
		tb.frameData = append(tb.frameData, []any{locIdx, false, nil, nil, nil, nil, catOther, 0})
		tb.frameKeys[key] = idx
		return idx
	}

	frame := ft[rbFrameIdx]
	funcName := lookupString(tb.capture.StringTable, frame.FunctionNameIdx)
	fileName := lookupString(tb.capture.StringTable, frame.FileNameIdx)

	// Build label: "ClassName#method (file.rb:42)"
	label := funcName
	if fileName != "" && frame.LineNumber > 0 {
		label = fmt.Sprintf("%s (%s:%d)", funcName, fileName, frame.LineNumber)
	} else if fileName != "" {
		label = fmt.Sprintf("%s (%s)", funcName, fileName)
	}

	key := fmt.Sprintf("%s:%d", label, frame.LineNumber)
	if idx, ok := tb.frameKeys[key]; ok {
		return idx
	}

	locIdx := tb.internString(label)
	var line any
	if frame.LineNumber > 0 {
		line = int(frame.LineNumber)
	}

	// Determine category from file path (App, Rails, gem, Ruby, cfunc, Native)
	cat, subcat := categorizeFrame(fileName)

	idx := len(tb.frameData)
	tb.frameData = append(tb.frameData, []any{locIdx, false, nil, nil, line, nil, cat, subcat})
	tb.frameKeys[key] = idx
	return idx
}

// internStack converts leaf-first frame IDs to a prefix-tree stack entry.
// Stack tuple: [prefix, frame]  where prefix is null or a stack index.
func (tb *threadBuilder) internStack(frameIDs []uint32) int {
	if len(frameIDs) == 0 {
		return -1
	}

	// Build prefix tree root→leaf. frameIDs are leaf-first, so reverse.
	var prefix any // nil for root
	for i := len(frameIDs) - 1; i >= 0; i-- {
		frameIdx := tb.internFrame(frameIDs[i])

		var prefixKey string
		if prefix == nil {
			prefixKey = fmt.Sprintf("nil:%d", frameIdx)
		} else {
			prefixKey = fmt.Sprintf("%d:%d", prefix, frameIdx)
		}

		if idx, ok := tb.stackKeys[prefixKey]; ok {
			prefix = idx
			continue
		}

		idx := len(tb.stackData)
		tb.stackData = append(tb.stackData, []any{prefix, frameIdx})
		tb.stackKeys[prefixKey] = idx
		prefix = idx
	}

	return prefix.(int)
}

func (tb *threadBuilder) nsToMs(ns uint64) float64 {
	return float64(ns)/1e6 - tb.startTimeMs
}

// --- Build a thread ---

func buildThread(capture *pb.Capture, tl *pb.ThreadTimeline, startTimeMs float64) Thread {
	tb := newThreadBuilder(capture, startTimeMs)

	name := "(unknown)"
	if int(tl.ThreadNameIdx) < len(capture.StringTable) && tl.ThreadNameIdx > 0 {
		name = capture.StringTable[tl.ThreadNameIdx]
	}

	samples := buildSamples(tb, tl)
	markers := buildMarkers(tb, tl)

	return Thread{
		Name:           name,
		RegisterTime:   0,
		ProcessType:    "default",
		UnregisterTime: nil,
		TID:            int(tl.ThreadId),
		PID:            int(capture.Header.Pid),
		Samples:        samples,
		Markers:        markers,
		FrameTable: FrameTableData{
			Schema: FrameTupleSchema{
				Location: 0, RelevantForJS: 1, InnerWindowID: 2,
				Implementation: 3, Line: 4, Column: 5, Category: 6, Subcategory: 7,
			},
			Data: tb.frameData,
		},
		StackTable: StackTableData{
			Schema: StackTupleSchema{Prefix: 0, Frame: 1},
			Data:   tb.stackData,
		},
		StringTable: tb.strings,
	}
}

func buildSamples(tb *threadBuilder, tl *pb.ThreadTimeline) SamplesTable {
	data := make([][]any, 0, len(tl.Samples))

	for _, s := range tl.Samples {
		var stackRef any
		stackIdx := tb.internStack(s.FrameIds)
		if stackIdx >= 0 {
			stackRef = stackIdx
		}

		timeMs := tb.nsToMs(s.TimestampNs)

		// For weighted samples, emit multiple entries or use eventDelay=0
		data = append(data, []any{stackRef, timeMs, 0})
	}

	return SamplesTable{
		Schema: SampleTupleSchema{Stack: 0, Time: 1, EventDelay: 2},
		Data:   data,
	}
}

func buildMarkers(tb *threadBuilder, tl *pb.ThreadTimeline) MarkersTable {
	data := make([][]any, 0)

	// I/O event markers
	for _, io := range tl.IoEvents {
		endMs := tb.nsToMs(io.TimestampNs)
		startMs := endMs - float64(io.LatencyNs)/1e6
		if startMs < 0 {
			startMs = 0
		}

		syscall := lookupString(tb.capture.StringTable, io.SyscallIdx)
		fdInfo := lookupString(tb.capture.StringTable, io.FdInfoIdx)

		nameIdx := tb.internString("I/O")
		data = append(data, []any{
			nameIdx, startMs, endMs, MarkerPhaseInterval, catIO,
			map[string]any{
				"type":      "rbscope-io",
				"syscall":   syscall,
				"fd":        io.Fd,
				"fdInfo":    fdInfo,
				"bytes":     io.Bytes,
				"latencyMs": float64(io.LatencyNs) / 1e6,
			},
		})
	}

	// Sched event markers (off-CPU periods)
	for _, sched := range tl.SchedEvents {
		endMs := tb.nsToMs(sched.TimestampNs)
		startMs := endMs - float64(sched.OffCpuNs)/1e6
		if startMs < 0 {
			startMs = 0
		}

		nameIdx := tb.internString("Off-CPU")
		data = append(data, []any{
			nameIdx, startMs, endMs, MarkerPhaseInterval, catNative,
			map[string]any{
				"type":     "rbscope-sched",
				"offCpuMs": float64(sched.OffCpuNs) / 1e6,
				"reason":   sched.Reason.String(),
			},
		})
	}

	// GVL wait markers
	for _, gvl := range tl.GvlEvents {
		endMs := tb.nsToMs(gvl.TimestampNs)
		startMs := endMs - float64(gvl.WaitNs)/1e6
		if startMs < 0 {
			startMs = 0
		}

		nameIdx := tb.internString("GVL Wait")
		data = append(data, []any{
			nameIdx, startMs, endMs, MarkerPhaseInterval, catGVL,
			map[string]any{
				"type":   "rbscope-gvl",
				"waitMs": float64(gvl.WaitNs) / 1e6,
			},
		})
	}

	// Span event markers
	for _, span := range tl.SpanEvents {
		startMs := tb.nsToMs(span.StartNs)
		endMs := startMs + float64(span.DurationNs)/1e6

		operation := lookupString(tb.capture.StringTable, span.OperationIdx)
		component := lookupString(tb.capture.StringTable, span.ComponentIdx)

		nameIdx := tb.internString("Span")
		payload := map[string]any{
			"type":       "rbscope-span",
			"operation":  operation,
			"component":  component,
			"durationMs": float64(span.DurationNs) / 1e6,
		}
		if span.OtelContext != nil {
			payload["traceId"] = fmt.Sprintf("%x", span.OtelContext.TraceId)
			payload["spanId"] = fmt.Sprintf("%x", span.OtelContext.SpanId)
		}

		data = append(data, []any{
			nameIdx, startMs, endMs, MarkerPhaseInterval, catOTel, payload,
		})
	}

	// Thread state markers
	for _, state := range tl.States {
		startMs := tb.nsToMs(state.StartNs)
		endMs := tb.nsToMs(state.EndNs)
		cat := threadStateToCat(state.State)
		label := threadStateLabel(state.State)

		nameIdx := tb.internString(label)
		data = append(data, []any{
			nameIdx, startMs, endMs, MarkerPhaseInterval, cat,
			map[string]any{
				"type":  "rbscope-state",
				"state": state.State.String(),
			},
		})
	}

	return MarkersTable{
		Schema: MarkerTupleSchema{
			Name: 0, StartTime: 1, EndTime: 2, Phase: 3, Category: 4, Data: 5,
		},
		Data: data,
	}
}

// --- Helpers ---

func lookupString(table []string, idx uint32) string {
	if int(idx) < len(table) {
		return table[idx]
	}
	return ""
}

// isNativeFrame returns true if the file path looks like a native library
// rather than a Ruby source file.
func isNativeFrame(path string) bool {
	return strings.HasSuffix(path, ".so") ||
		strings.Contains(path, ".so.") ||
		strings.HasSuffix(path, ".dylib") ||
		strings.HasPrefix(path, "[") // [vdso], [vsyscall]
}

// railsComponents lists all Rails framework gem names.
var railsComponents = []string{
	"activesupport", "activemodel", "activerecord", "actionview",
	"actionpack", "activejob", "actionmailer", "actioncable",
	"activestorage", "actionmailbox", "actiontext", "railties",
}

func railsSubcategories() []string {
	subs := make([]string, len(railsComponents))
	copy(subs, railsComponents)
	return subs
}

// categorizeFrame determines the category and subcategory for a Ruby frame
// based on its file path. Follows Vernier's PR #121 approach:
//
//	App code (app/, lib/, config/) → green
//	Rails (activerecord, actionview, ...) → red
//	Gems (/gems/) → lightblue
//	Ruby stdlib → purple
//	cfunc (<cfunc>) → yellow
//	Native (.so, .dylib) → blue
func categorizeFrame(fileName string) (cat, subcat int) {
	if fileName == "" {
		return catApp, 0
	}

	// Native C code — .so, .dylib, [vdso]
	if isNativeFrame(fileName) {
		return catNative, 0
	}

	// cfunc marker
	if fileName == "<cfunc>" {
		return catCfunc, 0
	}

	// GC
	if fileName == "(gc)" || strings.HasPrefix(fileName, "<internal:gc") {
		return catGC, 0
	}

	// Ruby internals: <internal:...>
	if strings.HasPrefix(fileName, "<internal:") {
		return catRuby, 1 // core
	}

	// Rails framework — check before generic gem path
	for i, component := range railsComponents {
		// Match paths like:
		//   /gems/activerecord-8.1.0/lib/...  (production, bundler)
		//   activerecord/lib/...               (dev/relative)
		if strings.Contains(fileName, "/"+component+"-") ||
			strings.Contains(fileName, "/"+component+"/") ||
			strings.HasPrefix(fileName, component+"/") ||
			strings.HasPrefix(fileName, component+"-") {
			return catRails, i
		}
	}

	// Third-party gems: /gems/ in path
	if strings.Contains(fileName, "/gems/") ||
		strings.Contains(fileName, "/bundler/") {
		return catGem, 0
	}

	// Ruby stdlib: /lib/ruby/ in path
	if strings.Contains(fileName, "/lib/ruby/") {
		return catRuby, 0 // stdlib
	}

	// Application code — everything else (app/, lib/, config/, spec/, etc.)
	return catApp, 0
}

func threadStateToCat(s pb.ThreadState) int {
	switch s {
	case pb.ThreadState_THREAD_STATE_RUNNING:
		return catApp
	case pb.ThreadState_THREAD_STATE_OFF_CPU_IO:
		return catIO
	case pb.ThreadState_THREAD_STATE_OFF_CPU_GVL:
		return catGVL
	case pb.ThreadState_THREAD_STATE_GC:
		return catGC
	case pb.ThreadState_THREAD_STATE_IDLE:
		return catIdle
	case pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED,
		pb.ThreadState_THREAD_STATE_OFF_CPU_UNKNOWN:
		return catNative
	default:
		return catOther
	}
}

func threadStateLabel(s pb.ThreadState) string {
	switch s {
	case pb.ThreadState_THREAD_STATE_RUNNING:
		return "Running"
	case pb.ThreadState_THREAD_STATE_OFF_CPU_IO:
		return "I/O Blocked"
	case pb.ThreadState_THREAD_STATE_OFF_CPU_GVL:
		return "GVL Wait"
	case pb.ThreadState_THREAD_STATE_OFF_CPU_MUTEX:
		return "Mutex Wait"
	case pb.ThreadState_THREAD_STATE_OFF_CPU_SLEEP:
		return "Sleep"
	case pb.ThreadState_THREAD_STATE_OFF_CPU_PREEMPTED:
		return "Preempted"
	case pb.ThreadState_THREAD_STATE_GC:
		return "GC"
	case pb.ThreadState_THREAD_STATE_IDLE:
		return "Idle"
	default:
		return "Off-CPU"
	}
}

// --- Default categories and marker schemas ---

func defaultCategories() []Category {
	return []Category{
		{Name: "Other", Color: "grey", Subcategories: []string{"Other"}},
		{Name: "App", Color: "green", Subcategories: []string{"Controller", "Model", "Job", "Mailer", "View"}},
		{Name: "Rails", Color: "red", Subcategories: railsSubcategories()},
		{Name: "gem", Color: "lightblue", Subcategories: []string{"gem"}},
		{Name: "Ruby", Color: "purple", Subcategories: []string{"stdlib", "core"}},
		{Name: "cfunc", Color: "yellow", Subcategories: []string{"cfunc"}},
		{Name: "Native", Color: "blue", Subcategories: []string{"C Extension", "System Library"}},
		{Name: "I/O", Color: "orange", Subcategories: []string{"Network", "File"}},
		{Name: "GVL", Color: "magenta", Subcategories: []string{"Wait"}},
		{Name: "GC", Color: "brown", Subcategories: []string{"GC"}},
		{Name: "OTel", Color: "lightgreen", Subcategories: []string{"Span"}},
		{Name: "Idle", Color: "grey", Subcategories: []string{"Idle"}},
	}
}

func defaultMarkerSchemas() []MarkerSchema {
	searchable := true
	return []MarkerSchema{
		{
			Name:         "rbscope-io",
			Display:      []string{"marker-chart", "marker-table", "timeline-fileio"},
			TooltipLabel: "I/O: {marker.data.syscall} on {marker.data.fdInfo}",
			TableLabel:   "{marker.data.syscall} {marker.data.fdInfo} ({marker.data.bytes} bytes)",
			ChartLabel:   "{marker.data.syscall}",
			Data: []SchemaField{
				{Key: "syscall", Label: "Syscall", Format: "string", Searchable: &searchable},
				{Key: "fd", Label: "FD", Format: "integer"},
				{Key: "fdInfo", Label: "Target", Format: "string", Searchable: &searchable},
				{Key: "bytes", Label: "Bytes", Format: "bytes"},
				{Key: "latencyMs", Label: "Latency", Format: "duration"},
			},
		},
		{
			Name:         "rbscope-sched",
			Display:      []string{"marker-chart", "marker-table"},
			TooltipLabel: "Off-CPU: {marker.data.reason}",
			TableLabel:   "Off-CPU {marker.data.offCpuMs}ms ({marker.data.reason})",
			ChartLabel:   "Off-CPU",
			Data: []SchemaField{
				{Key: "offCpuMs", Label: "Duration", Format: "duration"},
				{Key: "reason", Label: "Reason", Format: "string"},
			},
		},
		{
			Name:         "rbscope-gvl",
			Display:      []string{"marker-chart", "marker-table", "timeline-overview"},
			TooltipLabel: "GVL Wait: {marker.data.waitMs}ms",
			TableLabel:   "GVL Wait {marker.data.waitMs}ms",
			ChartLabel:   "GVL",
			Data: []SchemaField{
				{Key: "waitMs", Label: "Wait Duration", Format: "duration"},
			},
		},
		{
			Name:         "rbscope-span",
			Display:      []string{"marker-chart", "marker-table", "timeline-overview"},
			TooltipLabel: "Span: {marker.data.operation}",
			TableLabel:   "{marker.data.operation} ({marker.data.component})",
			ChartLabel:   "{marker.data.operation}",
			Data: []SchemaField{
				{Key: "operation", Label: "Operation", Format: "string", Searchable: &searchable},
				{Key: "component", Label: "Component", Format: "string"},
				{Key: "traceId", Label: "Trace ID", Format: "string"},
				{Key: "spanId", Label: "Span ID", Format: "string"},
				{Key: "durationMs", Label: "Duration", Format: "duration"},
			},
		},
		{
			Name:         "rbscope-state",
			Display:      []string{"marker-chart", "marker-table", "timeline-overview"},
			TooltipLabel: "{marker.data.state}",
			TableLabel:   "{marker.data.state}",
			ChartLabel:   "{marker.data.state}",
			Data: []SchemaField{
				{Key: "state", Label: "State", Format: "string"},
			},
		},
	}
}
