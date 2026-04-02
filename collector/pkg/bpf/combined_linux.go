//go:build linux

package bpf

import (
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// CombinedBPF runs both the gem's USDT probe reader (RealBPF) and the BPF
// stack walker (StackWalkerBPF) simultaneously.
//
// Architecture: each kernel ring buffer gets a dedicated drain goroutine
// that pushes into a per-reader Go channel. The consumer (ReadRingBuffer)
// uses fair round-robin across channels so no single high-volume source
// (like GVL) can starve others (like CPU samples).
//
// With BPF-side hysteresis (100µs minimum state duration), GVL event
// volume is manageable (~500/sec). The per-reader channels + async drain
// goroutines decouple kernel ring buffer draining from event processing
// (frame resolution takes milliseconds per stack walk event).
type CombinedBPF struct {
	gem    *RealBPF
	walker *StackWalkerBPF

	chans  []chan []byte  // per-reader channels
	stopCh chan struct{}  // signals drain goroutines to exit
	wg     sync.WaitGroup // tracks drain goroutines
	toggle int            // round-robin state

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
		_ = gem.Close()
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

// Load initializes both BPF programs and starts drain goroutines.
func (c *CombinedBPF) Load() error {
	if err := c.gem.Load(); err != nil {
		return fmt.Errorf("gem load: %w", err)
	}
	if err := c.walker.Load(); err != nil {
		return fmt.Errorf("walker load: %w", err)
	}

	c.stopCh = make(chan struct{})

	// Each reader gets a dedicated channel and drain goroutine.
	type readerEntry struct {
		rd   *ringbuf.Reader
		size int
	}
	var entries []readerEntry

	if c.walker.reader != nil {
		entries = append(entries, readerEntry{c.walker.reader, 4096})
	}
	if c.gem.reader != nil {
		entries = append(entries, readerEntry{c.gem.reader, 8192})
	}
	if c.walker.ioReader != nil {
		entries = append(entries, readerEntry{c.walker.ioReader, 4096})
	}
	if c.walker.schedReader != nil {
		entries = append(entries, readerEntry{c.walker.schedReader, 2048})
	}
	if c.gem.gvlReader != nil {
		entries = append(entries, readerEntry{c.gem.gvlReader, 1 << 18}) // 256K
	}
	if c.gem.gvlStackReader != nil {
		entries = append(entries, readerEntry{c.gem.gvlStackReader, 8192})
	}

	c.chans = make([]chan []byte, len(entries))
	for i, e := range entries {
		c.chans[i] = make(chan []byte, e.size)
		c.wg.Add(1)
		go c.drainReader(e.rd, c.chans[i])
	}

	return nil
}

// drainReader continuously reads from a single kernel ring buffer and pushes
// raw event copies into its dedicated channel.
func (c *CombinedBPF) drainReader(rd *ringbuf.Reader, ch chan []byte) {
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

		data := make([]byte, len(record.RawSample))
		copy(data, record.RawSample)

		select {
		case ch <- data:
		case <-c.stopCh:
			return
		}
	}
}

// AttachPID attaches both gem and walker probes to the target process.
func (c *CombinedBPF) AttachPID(pid uint32) error {
	if err := c.gem.AttachPID(pid); err != nil {
		return fmt.Errorf("gem attach: %w", err)
	}
	if err := c.walker.AttachPID(pid); err != nil {
		return fmt.Errorf("walker attach: %w", err)
	}
	return nil
}

// DetachPID detaches probes from the target process.
func (c *CombinedBPF) DetachPID(pid uint32) error {
	_ = c.gem.DetachPID(pid)
	return c.walker.DetachPID(pid)
}

// ReadRingBuffer returns the next event using fair round-robin across
// per-reader channels. With BPF-side hysteresis filtering, GVL event
// volume is ~500/sec (down from ~5000/sec), making simple round-robin
// sufficient for balanced consumption.
func (c *CombinedBPF) ReadRingBuffer(buf []byte) (int, error) {
	if len(c.chans) == 0 {
		return 0, nil
	}

	// Fast path: round-robin non-blocking check.
	for i := 0; i < len(c.chans); i++ {
		idx := (c.toggle + i) % len(c.chans)
		select {
		case data := <-c.chans[idx]:
			c.toggle = (idx + 1) % len(c.chans)
			return copy(buf, data), nil
		default:
		}
	}

	// Slow path: wait up to 10ms for any channel.
	t := c.readTimer
	if t == nil {
		t = time.NewTimer(10 * time.Millisecond)
		c.readTimer = t
	} else {
		t.Reset(10 * time.Millisecond)
	}
	for {
		for i := 0; i < len(c.chans); i++ {
			idx := (c.toggle + i) % len(c.chans)
			select {
			case data := <-c.chans[idx]:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				c.toggle = (idx + 1) % len(c.chans)
				return copy(buf, data), nil
			default:
			}
		}
		select {
		case <-t.C:
			return 0, nil
		default:
			time.Sleep(100 * time.Microsecond)
		}
	}
}

// KtimeOffsetNs returns the ktime-to-wallclock offset from the stack walker.
func (c *CombinedBPF) KtimeOffsetNs() int64 {
	return c.walker.KtimeOffsetNs()
}

// Close stops drain goroutines and releases both BPF programs.
func (c *CombinedBPF) Close() error {
	close(c.stopCh)
	c.wg.Wait()

	for _, ch := range c.chans {
		close(ch)
		for range ch { //nolint:revive // drain remaining buffered events
		}
	}

	_ = c.gem.Close()
	return c.walker.Close()
}
