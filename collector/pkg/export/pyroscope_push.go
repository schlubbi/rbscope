package export

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/pprof/profile"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// PyroscopePushExporter implements collector.Exporter by accumulating stack
// samples into a pprof profile and periodically pushing to Pyroscope.
type PyroscopePushExporter struct {
	pyro       *PyroscopeExporter
	log        *slog.Logger
	symbolMap  map[uint32][]string // stackID → function names
	flushEvery time.Duration

	mu      sync.Mutex
	builder *profile.Profile
	funcMap map[string]*profile.Function
	locMap  map[uint64]*profile.Location
	funcID  uint64
	locID   uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PyroscopePushConfig configures the push exporter.
type PyroscopePushConfig struct {
	ServerURL  string
	AppName    string
	Labels     map[string]string
	SymbolMap  map[uint32][]string // stackID → frame names (for demo mode)
	FlushEvery time.Duration
	Logger     *slog.Logger
}

// NewPyroscopePushExporter creates an exporter that pushes profiles to Pyroscope.
func NewPyroscopePushExporter(cfg PyroscopePushConfig) *PyroscopePushExporter {
	if cfg.FlushEvery == 0 {
		cfg.FlushEvery = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &PyroscopePushExporter{
		pyro: NewPyroscopeExporter(PyroscopeConfig{
			ServerURL: cfg.ServerURL,
			AppName:   cfg.AppName,
			Labels:    cfg.Labels,
		}),
		log:        cfg.Logger,
		symbolMap:  cfg.SymbolMap,
		flushEvery: cfg.FlushEvery,
		funcMap:    make(map[string]*profile.Function),
		locMap:     make(map[uint64]*profile.Location),
		ctx:        ctx,
		cancel:     cancel,
	}
	e.resetProfile()

	e.wg.Add(1)
	go e.flushLoop()

	return e
}

// Export handles a decoded event from the collector.
func (e *PyroscopePushExporter) Export(_ context.Context, event any) error {
	sample, ok := event.(*collector.RubySampleEvent)
	if !ok {
		return nil // skip non-sample events
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	locs := e.resolveStack(sample)
	if len(locs) == 0 {
		return nil
	}

	e.builder.Sample = append(e.builder.Sample, &profile.Sample{
		Location: locs,
		Value:    []int64{1, 10000000}, // 1 sample, 10ms cpu
	})
	return nil
}

// Flush pushes the accumulated profile to Pyroscope.
func (e *PyroscopePushExporter) Flush(ctx context.Context) error {
	return e.pushProfile(ctx)
}

// Close stops the background flush loop and pushes remaining data.
func (e *PyroscopePushExporter) Close() error {
	e.cancel()
	e.wg.Wait()
	return e.pushProfile(context.Background())
}

func (e *PyroscopePushExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.pushProfile(e.ctx); err != nil {
				e.log.Warn("pyroscope flush failed", "err", err)
			}
		}
	}
}

func (e *PyroscopePushExporter) pushProfile(ctx context.Context) error {
	e.mu.Lock()
	prof := e.builder
	sampleCount := len(prof.Sample)
	e.resetProfile()
	e.mu.Unlock()

	if sampleCount == 0 {
		return nil
	}

	prof.DurationNanos = e.flushEvery.Nanoseconds()
	prof.TimeNanos = time.Now().UnixNano()

	if err := e.pyro.Push(ctx, prof); err != nil {
		return fmt.Errorf("pyroscope push (%d samples): %w", sampleCount, err)
	}

	e.log.Info("pushed profile to pyroscope", "samples", sampleCount)
	return nil
}

func (e *PyroscopePushExporter) resetProfile() {
	e.builder = &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: "nanoseconds"},
		},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:     int64(10000000), // 10ms = 100Hz equivalent
	}
	e.funcMap = make(map[string]*profile.Function)
	e.locMap = make(map[uint64]*profile.Location)
	e.funcID = 0
	e.locID = 0
}

func (e *PyroscopePushExporter) resolveStack(sample *collector.RubySampleEvent) []*profile.Location {
	// Parse inline format v2 stack data from the BPF event
	frames := collector.ParseInlineStack(sample.StackData)
	if len(frames) == 0 {
		// Fall back to demo-mode symbolMap if no inline data
		if e.symbolMap != nil {
			return e.resolveFromSymbolMap(sample)
		}
		return nil
	}

	locs := make([]*profile.Location, 0, len(frames))
	for _, frame := range frames {
		name := frame.Label
		if name == "" {
			name = "<unknown>"
		}
		filename := frame.Path
		line := int64(frame.Line)

		addr := hashName(name + filename)
		loc, exists := e.locMap[addr]
		if !exists {
			fn := e.getOrCreateFunc(name)
			fn.Filename = filename
			e.locID++
			loc = &profile.Location{
				ID:      e.locID,
				Address: addr,
				Line: []profile.Line{
					{Function: fn, Line: line},
				},
			}
			e.locMap[addr] = loc
			e.builder.Location = append(e.builder.Location, loc)
		}
		locs = append(locs, loc)
	}
	return locs
}

// resolveFromSymbolMap resolves stacks using pre-loaded symbol names (demo mode).
func (e *PyroscopePushExporter) resolveFromSymbolMap(sample *collector.RubySampleEvent) []*profile.Location {
	names, ok := e.symbolMap[sample.StackDataLen] // reuse StackDataLen as stack ID for demo
	if !ok {
		return nil
	}

	locs := make([]*profile.Location, 0, len(names))
	for _, name := range names {
		addr := hashName(name)
		loc, exists := e.locMap[addr]
		if !exists {
			fn := e.getOrCreateFunc(name)
			e.locID++
			loc = &profile.Location{
				ID:      e.locID,
				Address: addr,
				Line: []profile.Line{
					{Function: fn, Line: 1},
				},
			}
			e.locMap[addr] = loc
			e.builder.Location = append(e.builder.Location, loc)
		}
		locs = append(locs, loc)
	}
	return locs
}

func (e *PyroscopePushExporter) getOrCreateFunc(name string) *profile.Function {
	if fn, ok := e.funcMap[name]; ok {
		return fn
	}
	e.funcID++
	fn := &profile.Function{
		ID:   e.funcID,
		Name: name,
	}
	e.funcMap[name] = fn
	e.builder.Function = append(e.builder.Function, fn)
	return fn
}

// hashName produces a stable pseudo-address from a function name.
func hashName(s string) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range s {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
