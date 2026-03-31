//go:build linux

package bpf

import (
	"fmt"
	"sync"
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
// Architecture: each kernel ring buffer gets a dedicated drain goroutine
// that reads as fast as the kernel provides data and pushes raw events
// into a shared Go channel. This decouples ring buffer draining from
// event processing (frame resolution, symbol lookup, etc.) — the
// collector can spend milliseconds resolving a stack walk frame without
// starving high-volume readers like GVL.
//
// Backpressure: the Go channel (64K deep) absorbs bursts. Drain goroutines
// only block when the channel is full AND the kernel ring buffer is full,
// requiring tens of seconds of sustained backlog.
type CombinedBPF struct {
	gem    *RealBPF
	walker *StackWalkerBPF

	readers []*ringbuf.Reader

	eventCh chan []byte     // drained events for the collector
	stopCh  chan struct{}   // signals drain goroutines to exit
	wg      sync.WaitGroup // tracks drain goroutines

	readTimer *time.Timer // reused by ReadRingBuffer to avoid alloc per call
}

// NewCombinedBPF creates a combined profiler.
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

	// Collect all non-nil readers.
	c.readers = nil
	if c.walker.reader != nil {
		c.readers = append(c.readers, c.walker.reader)
	}
	if c.gem.reader != nil {
		c.readers = append(c.readers, c.gem.reader)
	}
	if c.gem.gvlReader != nil {
		c.readers = append(c.readers, c.gem.gvlReader)
	}
	if c.gem.gvlStackReader != nil {
		c.readers = append(c.readers, c.gem.gvlStackReader)
	}
	if c.walker.ioReader != nil {
		c.readers = append(c.readers, c.walker.ioReader)
	}
	if c.walker.schedReader != nil {
		c.readers = append(c.readers, c.walker.schedReader)
	}

	// 64K-deep channel. At ~5000 GVL events/sec + ~100 CPU + ~500 I/O,
	// this holds ~10 seconds of events before drain goroutines block.
	c.eventCh = make(chan []byte, 1<<16)
	c.stopCh = make(chan struct{})

	// One drain goroutine per reader. Each reads from its kernel ring buffer
	// as fast as epoll delivers events and pushes into the shared channel.
	for _, rd := range c.readers {
		c.wg.Add(1)
		go c.drainReader(rd)
	}

	return nil
}

// drainReader continuously reads from a single kernel ring buffer and pushes
// raw event copies into the shared channel.
func (c *CombinedBPF) drainReader(rd *ringbuf.Reader) {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		rd.SetDeadline(time.Now().Add(50 * time.Millisecond))
		record, err := rd.Read()
		if err != nil {
			continue
		}

		// Copy — the reader reuses its internal buffer on next Read().
		data := make([]byte, len(record.RawSample))
		copy(data, record.RawSample)

		select {
		case c.eventCh <- data:
		case <-c.stopCh:
			return
		}
	}
}

func (c *CombinedBPF) AttachPID(pid uint32) error {
	if err := c.gem.AttachPID(pid); err != nil {
		return fmt.Errorf("gem attach: %w", err)
	}
	if err := c.walker.AttachPID(pid); err != nil {
		return fmt.Errorf("walker attach: %w", err)
	}
	return nil
}

func (c *CombinedBPF) DetachPID(pid uint32) error {
	_ = c.gem.DetachPID(pid)
	return c.walker.DetachPID(pid)
}

// ReadRingBuffer returns the next event from the channel, or 0 if none
// are available within 10ms. Uses a reusable timer to avoid per-call
// allocations under high throughput.
func (c *CombinedBPF) ReadRingBuffer(buf []byte) (int, error) {
	// Fast path: non-blocking check first.
	select {
	case data := <-c.eventCh:
		return copy(buf, data), nil
	default:
	}

	// Slow path: wait up to 10ms.
	t := c.readTimer
	if t == nil {
		t = time.NewTimer(10 * time.Millisecond)
		c.readTimer = t
	} else {
		t.Reset(10 * time.Millisecond)
	}
	select {
	case data := <-c.eventCh:
		if !t.Stop() {
			<-t.C
		}
		return copy(buf, data), nil
	case <-t.C:
		return 0, nil
	}
}

func (c *CombinedBPF) KtimeOffsetNs() int64 {
	return c.walker.KtimeOffsetNs()
}

func (c *CombinedBPF) Close() error {
	close(c.stopCh)
	c.wg.Wait()

	// Drain remaining channel events.
	close(c.eventCh)
	for range c.eventCh {
	}

	_ = c.gem.Close()
	return c.walker.Close()
}
