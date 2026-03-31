//go:build linux

package bpf

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// CombinedBPF runs both the gem's USDT probe reader (RealBPF) and the BPF
// stack walker (StackWalkerBPF) simultaneously. This produces a unified
// profile with:
//
//   - CPU samples from BPF perf_event stack walking (99 Hz)
//   - Allocation tracking from gem USDT probes (sampled)
//   - GVL state markers from gem USDT probes
//   - I/O markers from kernel tracepoints
//   - Scheduler state from sched tracepoints
//
// The gem's own CPU sampler is redundant — BPF provides higher-frequency,
// zero-instrumentation stack walking. The gem is used only for allocation
// and GVL hooks that require in-process instrumentation.
type CombinedBPF struct {
	gem     *RealBPF
	walker  *StackWalkerBPF
	toggle  int
	readers []*ringbuf.Reader // all readers to poll
	pending [][]byte          // batch-drained events waiting for delivery
}

// NewCombinedBPF creates a combined profiler.
//   - bpfObj: path to the gem's compiled BPF object
//   - rubyPath: path to libruby (or statically-linked ruby binary)
//   - cpuHz: sampling frequency for BPF stack walker (typically 99)
func NewCombinedBPF(bpfObj, rubyPath string, cpuHz int) (*CombinedBPF, error) {
	gem, err := NewRealBPF(bpfObj)
	if err != nil {
		return nil, fmt.Errorf("create gem BPF: %w", err)
	}

	walker, err := NewStackWalkerBPF(rubyPath, cpuHz)
	if err != nil {
		gem.Close()
		return nil, fmt.Errorf("create stack walker: %w", err)
	}

	// In combined mode, BPF stack walker handles CPU sampling and I/O+sched tracing.
	// Disable these in the gem to avoid redundant overhead and event duplication.
	gem.SkipCPUSampler = true
	gem.SkipIOSched = true

	return &CombinedBPF{
		gem:    gem,
		walker: walker,
	}, nil
}

// Walker returns the underlying StackWalkerBPF for offset/PID mapping access.
func (c *CombinedBPF) Walker() *StackWalkerBPF {
	return c.walker
}

func (c *CombinedBPF) Load() error {
	if err := c.gem.Load(); err != nil {
		return fmt.Errorf("gem load: %w", err)
	}
	if err := c.walker.Load(); err != nil {
		return fmt.Errorf("walker load: %w", err)
	}

	// Collect all non-nil readers for round-robin polling.
	// Walker provides: CPU stack walks, I/O, sched
	// Gem provides: alloc probes, GVL state, GVL stacks
	// We DON'T include the gem's primary reader (ruby samples) —
	// BPF stack walker handles CPU sampling. We also skip the gem's
	// I/O and sched readers since the walker already has them.
	c.readers = nil
	// Primary: BPF stack walker (CPU samples)
	if c.walker.reader != nil {
		c.readers = append(c.readers, c.walker.reader)
	}
	// Gem alloc probes (the gem's primary ring buffer carries alloc events)
	if c.gem.reader != nil {
		c.readers = append(c.readers, c.gem.reader)
	}
	// GVL from gem
	if c.gem.gvlReader != nil {
		c.readers = append(c.readers, c.gem.gvlReader)
	}
	if c.gem.gvlStackReader != nil {
		c.readers = append(c.readers, c.gem.gvlStackReader)
	}
	// I/O + sched from walker (not gem — avoid duplicates)
	if c.walker.ioReader != nil {
		c.readers = append(c.readers, c.walker.ioReader)
	}
	if c.walker.schedReader != nil {
		c.readers = append(c.readers, c.walker.schedReader)
	}

	return nil
}

func (c *CombinedBPF) AttachPID(pid uint32) error {
	// Attach gem probes (alloc + GVL USDT uprobes)
	if err := c.gem.AttachPID(pid); err != nil {
		return fmt.Errorf("gem attach: %w", err)
	}
	// Attach stack walker (perf_event CPU sampling + EC discovery)
	if err := c.walker.AttachPID(pid); err != nil {
		return fmt.Errorf("walker attach: %w", err)
	}
	return nil
}

func (c *CombinedBPF) DetachPID(pid uint32) error {
	_ = c.gem.DetachPID(pid)
	return c.walker.DetachPID(pid)
}

func (c *CombinedBPF) ReadRingBuffer(buf []byte) (int, error) {
	if len(c.readers) == 0 {
		return 0, nil
	}

	// Drain pending events from the backlog first (batch-drained from
	// high-volume readers to prevent ring buffer overflow).
	if len(c.pending) > 0 {
		n := copy(buf, c.pending[0])
		c.pending = c.pending[1:]
		return n, nil
	}

	// Round-robin across all readers. When a reader has data, batch-drain
	// up to maxBatch events to prevent high-volume ring buffers (GVL, alloc)
	// from overflowing while the event loop processes expensive operations
	// like frame resolution.
	const maxBatch = 64
	start := c.toggle
	for attempt := 0; attempt < 2; attempt++ {
		deadline := 1 * time.Millisecond
		if attempt == 1 {
			deadline = 5 * time.Millisecond
		}
		for i := 0; i < len(c.readers); i++ {
			idx := (start + i) % len(c.readers)
			rd := c.readers[idx]
			rd.SetDeadline(time.Now().Add(deadline))
			record, err := rd.Read()
			if err == nil {
				c.toggle = (idx + 1) % len(c.readers)
				n := copy(buf, record.RawSample)

				// Batch-drain: pull more events from this reader while available.
				for j := 0; j < maxBatch; j++ {
					rd.SetDeadline(time.Now().Add(100 * time.Microsecond))
					extra, err := rd.Read()
					if err != nil {
						break
					}
					dup := make([]byte, len(extra.RawSample))
					copy(dup, extra.RawSample)
					c.pending = append(c.pending, dup)
				}

				return n, nil
			}
		}
	}

	return 0, nil
}

func (c *CombinedBPF) KtimeOffsetNs() int64 {
	return c.walker.KtimeOffsetNs()
}

func (c *CombinedBPF) Close() error {
	_ = c.gem.Close()
	return c.walker.Close()
}
