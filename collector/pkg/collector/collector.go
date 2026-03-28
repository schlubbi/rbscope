// Package collector implements the core event processing loop for rbscope.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Exporter receives decoded events from the collector.
type Exporter interface {
	// Export handles a single decoded event.
	Export(ctx context.Context, event any) error
	// Flush is called at the end of each collection interval.
	Flush(ctx context.Context) error
	// Close releases resources held by the exporter.
	Close() error
}

// BPFProgram abstracts the eBPF lifecycle so the collector compiles on any OS.
type BPFProgram interface {
	Load() error
	AttachPID(pid uint32) error
	DetachPID(pid uint32) error
	ReadRingBuffer(buf []byte) (int, error)
	Close() error
}

// Config holds collector configuration.
type Config struct {
	FrequencyHz int
	Exporters   []Exporter
	Logger      *slog.Logger
}

var (
	metricSamplesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "rbscope",
		Name:      "samples_total",
		Help:      "Total number of stack samples received from BPF.",
	})
	metricDropsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "rbscope",
		Name:      "drops_total",
		Help:      "Total number of events dropped (ring buffer full, parse errors, etc.).",
	})
	metricExportLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rbscope",
		Name:      "export_latency_seconds",
		Help:      "Latency of export operations.",
		Buckets:   prometheus.DefBuckets,
	})
	metricAttachedPIDs = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "rbscope",
		Name:      "attached_pids",
		Help:      "Number of currently attached PIDs.",
	})
)

// Collector orchestrates BPF program loading, event reading, and export.
type Collector struct {
	cfg  Config
	bpf  BPFProgram
	log  *slog.Logger
	pids map[uint32]struct{}
	mu   sync.Mutex

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a Collector. Pass nil for bpf to use a no-op stub (useful on
// non-Linux hosts or in tests).
func New(cfg Config, bpf BPFProgram) *Collector {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if bpf == nil {
		bpf = &stubBPF{}
	}
	return &Collector{
		cfg:  cfg,
		bpf:  bpf,
		log:  logger,
		pids: make(map[uint32]struct{}),
	}
}

// Start loads the BPF program and begins the event processing loop.
// It blocks until ctx is cancelled or Stop is called.
func (c *Collector) Start(ctx context.Context) error {
	if err := c.bpf.Load(); err != nil {
		return fmt.Errorf("bpf load: %w", err)
	}

	ctx, c.cancel = context.WithCancel(ctx)

	c.wg.Add(1)
	go c.eventLoop(ctx)

	c.log.Info("collector started", "frequency_hz", c.cfg.FrequencyHz)
	return nil
}

// Stop cancels the event loop, flushes exporters, and releases resources.
func (c *Collector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()

	for _, exp := range c.cfg.Exporters {
		if err := exp.Close(); err != nil {
			c.log.Warn("exporter close error", "err", err)
		}
	}
	return c.bpf.Close()
}

// AttachPID attaches BPF uprobes to the given process.
func (c *Collector) AttachPID(pid uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.pids[pid]; ok {
		return nil // already attached
	}
	if err := c.bpf.AttachPID(pid); err != nil {
		return fmt.Errorf("attach pid %d: %w", pid, err)
	}
	c.pids[pid] = struct{}{}
	metricAttachedPIDs.Set(float64(len(c.pids)))
	c.log.Info("attached pid", "pid", pid)
	return nil
}

// DetachPID removes BPF uprobes from the given process.
func (c *Collector) DetachPID(pid uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.pids[pid]; !ok {
		return nil
	}
	if err := c.bpf.DetachPID(pid); err != nil {
		return fmt.Errorf("detach pid %d: %w", pid, err)
	}
	delete(c.pids, pid)
	metricAttachedPIDs.Set(float64(len(c.pids)))
	c.log.Info("detached pid", "pid", pid)
	return nil
}

// eventLoop reads from the BPF ring buffer and dispatches events.
func (c *Collector) eventLoop(ctx context.Context) {
	defer c.wg.Done()
	buf := make([]byte, 64*1024) // 64 KiB read buffer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := c.bpf.ReadRingBuffer(buf)
		if err != nil {
			c.log.Debug("ring buffer read", "err", err)
			continue
		}
		if n == 0 {
			continue
		}

		event, err := ParseEvent(buf[:n])
		if err != nil {
			metricDropsTotal.Inc()
			c.log.Debug("parse event", "err", err)
			continue
		}

		metricSamplesTotal.Inc()

		timer := prometheus.NewTimer(metricExportLatency)
		for _, exp := range c.cfg.Exporters {
			if err := exp.Export(ctx, event); err != nil {
				c.log.Warn("export error", "err", err)
			}
		}
		timer.ObserveDuration()
	}
}

// stubBPF is a no-op implementation of BPFProgram for non-Linux or testing.
type stubBPF struct{}

func (s *stubBPF) Load() error                          { return nil }
func (s *stubBPF) AttachPID(_ uint32) error             { return nil }
func (s *stubBPF) DetachPID(_ uint32) error             { return nil }
func (s *stubBPF) ReadRingBuffer(_ []byte) (int, error) { return 0, nil }
func (s *stubBPF) Close() error                         { return nil }
