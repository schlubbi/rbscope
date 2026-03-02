//go:build linux

package bpf

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// bpfObjects mirrors the struct that bpf2go generates from ruby_reader.c.
// When go generate runs on Linux it will produce the real type; this
// placeholder lets the package compile before code-generation has run.
type bpfObjects struct {
	Events   *ebpf.Map     `ebpf:"events"`
	OnEntry  *ebpf.Program `ebpf:"on_entry"`
	OnReturn *ebpf.Program `ebpf:"on_return"`
}

func (o *bpfObjects) Close() error {
	if o.Events != nil {
		o.Events.Close()
	}
	if o.OnEntry != nil {
		o.OnEntry.Close()
	}
	if o.OnReturn != nil {
		o.OnReturn.Close()
	}
	return nil
}

// RealBPF is the Linux eBPF-backed implementation of collector.BPFProgram.
type RealBPF struct {
	objs   bpfObjects
	reader *ringbuf.Reader
	links  []link.Link
}

// Compile-time interface check.
var _ collector.BPFProgram = (*RealBPF)(nil)

// NewRealBPF returns a new RealBPF ready to be loaded.
func NewRealBPF() (*RealBPF, error) {
	return &RealBPF{}, nil
}

// Load opens the compiled BPF ELF and creates a ring-buffer reader.
func (r *RealBPF) Load() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(nil)
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}
	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	rd, err := ringbuf.NewReader(r.objs.Events)
	if err != nil {
		r.objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	r.reader = rd
	return nil
}

// AttachPID attaches a uprobe to the rbscope shared library mapped into the
// target process.
func (r *RealBPF) AttachPID(pid uint32) error {
	binPath := fmt.Sprintf("/proc/%d/root/usr/lib/librbscope.so", pid)
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("locate rbscope library for pid %d: %w", pid, err)
	}

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", binPath, err)
	}

	l, err := ex.Uprobe("rbscope_sample", r.objs.OnEntry, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		return fmt.Errorf("attach uprobe pid %d: %w", pid, err)
	}
	r.links = append(r.links, l)
	return nil
}

// DetachPID detaches all uprobes for the given PID.
func (r *RealBPF) DetachPID(pid uint32) error {
	remaining := r.links[:0]
	for _, l := range r.links {
		if err := l.Close(); err != nil {
			remaining = append(remaining, l)
		}
	}
	r.links = remaining
	return nil
}

// ReadRingBuffer reads a single record from the BPF ring buffer with a short
// poll timeout so the caller's event loop stays responsive.
func (r *RealBPF) ReadRingBuffer(buf []byte) (int, error) {
	r.reader.SetDeadline(time.Now().Add(50 * time.Millisecond))
	record, err := r.reader.Read()
	if err != nil {
		return 0, err
	}
	n := copy(buf, record.RawSample)
	return n, nil
}

// Close releases all BPF resources.
func (r *RealBPF) Close() error {
	for _, l := range r.links {
		l.Close()
	}
	if r.reader != nil {
		r.reader.Close()
	}
	r.objs.Close()
	return nil
}
