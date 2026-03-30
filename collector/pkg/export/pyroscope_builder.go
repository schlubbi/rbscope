package export

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/schlubbi/rbscope/collector/pkg/timeline"
)

// BuilderPyroscopeExporter routes events through a timeline.Builder to
// produce unified stacks (Ruby + native + syscall), then pushes the
// resulting pprof profile to Pyroscope on each flush interval.
//
// Unlike PyroscopePushExporter which only sees raw RubySampleEvents,
// this exporter gets the full Build() output including I/O-synthesized
// samples with C extension native frames.
type BuilderPyroscopeExporter struct {
	builder *timeline.Builder
	pyro    *PyroscopeExporter
	log     *slog.Logger

	flushEvery time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// BuilderPyroscopeConfig configures the builder-backed Pyroscope exporter.
type BuilderPyroscopeConfig struct {
	Builder    *timeline.Builder
	ServerURL  string
	AppName    string
	Labels     map[string]string
	FlushEvery time.Duration
	Logger     *slog.Logger
}

// NewBuilderPyroscopeExporter creates an exporter that accumulates events
// in a Builder, periodically calls Build() to produce unified stacks,
// converts to pprof, and pushes to Pyroscope.
func NewBuilderPyroscopeExporter(cfg BuilderPyroscopeConfig) *BuilderPyroscopeExporter {
	if cfg.FlushEvery == 0 {
		cfg.FlushEvery = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &BuilderPyroscopeExporter{
		builder: cfg.Builder,
		pyro: NewPyroscopeExporter(PyroscopeConfig{
			ServerURL: cfg.ServerURL,
			AppName:   cfg.AppName,
			Labels:    cfg.Labels,
		}),
		log:        cfg.Logger,
		flushEvery: cfg.FlushEvery,
		ctx:        ctx,
		cancel:     cancel,
	}

	e.wg.Add(1)
	go e.flushLoop()

	return e
}

// Export ingests an event into the Builder.
func (e *BuilderPyroscopeExporter) Export(_ context.Context, event any) error {
	e.builder.Ingest(event)
	return nil
}

// Flush builds the capture, converts to pprof, and pushes to Pyroscope.
func (e *BuilderPyroscopeExporter) Flush(ctx context.Context) error {
	return e.buildAndPush(ctx)
}

// Close stops the background flush loop and pushes remaining data.
func (e *BuilderPyroscopeExporter) Close() error {
	e.cancel()
	e.wg.Wait()
	return e.buildAndPush(context.Background())
}

func (e *BuilderPyroscopeExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.buildAndPush(e.ctx); err != nil {
				e.log.Warn("pyroscope flush failed", "err", err)
			}
		}
	}
}

func (e *BuilderPyroscopeExporter) buildAndPush(ctx context.Context) error {
	capture := e.builder.Build()
	e.builder.Reset()

	// Count samples and allocations across all threads.
	totalSamples := 0
	totalAllocs := 0
	for _, t := range capture.Threads {
		totalSamples += len(t.Samples)
		totalAllocs += len(t.Allocations)
	}
	if totalSamples == 0 && totalAllocs == 0 {
		return nil
	}

	now := time.Now().UnixNano()

	// Push CPU profile
	if totalSamples > 0 {
		prof := CaptureToProfile(capture)
		prof.DurationNanos = e.flushEvery.Nanoseconds()
		prof.TimeNanos = now
		if err := e.pyro.Push(ctx, prof); err != nil {
			return err
		}
	}

	// Push allocation profile (separate profile type)
	if totalAllocs > 0 {
		allocProf := CaptureToAllocProfile(capture)
		if allocProf != nil {
			allocProf.DurationNanos = e.flushEvery.Nanoseconds()
			allocProf.TimeNanos = now
			if err := e.pyro.PushWithName(ctx, allocProf, e.pyro.appName+".alloc_objects"); err != nil {
				e.log.Warn("pyroscope alloc push failed", "err", err)
			}
		}
	}

	e.log.Info("pushed unified profile to pyroscope", "samples", totalSamples, "allocs", totalAllocs)
	return nil
}
