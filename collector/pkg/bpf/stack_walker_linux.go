//go:build linux

package bpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
	"github.com/schlubbi/rbscope/collector/pkg/offsets"
	"golang.org/x/sys/unix"
)

// StackWalkerBPF is the zero-instrumentation BPF-based Ruby profiler.
// It uses perf_event sampling + BPF stack walking (no gem/USDT needed).
type StackWalkerBPF struct {
	objs          *stackwalkerObjects
	reader        *ringbuf.Reader
	perfFDs       []int    // perf_event file descriptors (one per CPU)
	perfLinks     []link.Link // perf_event → BPF program links
	rubyOffsets   *offsets.RubyOffsets
	ktimeOffsetNs int64
	frequencyHz   int
	// IO/GVL/sched tracers (shared with gem mode)
	ioObjs         *iotracerObjects
	ioReader       *ringbuf.Reader
	ioLinks        []link.Link
	gvlObjs        *gvltracerObjects
	gvlReader      *ringbuf.Reader
	gvlStackReader *ringbuf.Reader
	gvlLinks       []link.Link
	schedObjs      *schedtracerObjects
	schedReader    *ringbuf.Reader
	schedLinks     []link.Link
	readToggle     int
}

var _ collector.BPFProgram = (*StackWalkerBPF)(nil)

// NewStackWalkerBPF creates a new stack walker BPF loader.
// rubyPath is the path to libruby.so with DWARF debug info.
// frequencyHz is the sampling frequency (e.g. 99 Hz).
func NewStackWalkerBPF(rubyPath string, frequencyHz int) (*StackWalkerBPF, error) {
	off, err := offsets.ExtractFromDWARF(rubyPath)
	if err != nil {
		return nil, fmt.Errorf("extract DWARF offsets from %s: %w", rubyPath, err)
	}

	return &StackWalkerBPF{
		rubyOffsets: off,
		frequencyHz: frequencyHz,
	}, nil
}

// Load loads the BPF program and populates the offsets map.
func (s *StackWalkerBPF) Load() error {
	objs := &stackwalkerObjects{}
	if err := loadStackwalkerObjects(objs, nil); err != nil {
		return fmt.Errorf("load stack walker BPF: %w", err)
	}
	s.objs = objs

	// Write offsets to the BPF map
	bpfOff := s.rubyOffsets.ToBPF()
	key := uint32(0)
	if err := objs.RubyOffsetsMap.Put(key, bpfOff); err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("write ruby offsets to BPF map: %w", err)
	}

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.StackWalkerEvents)
	if err != nil {
		objs.Close() //nolint:errcheck
		return fmt.Errorf("open stack walker ring buffer: %w", err)
	}
	s.reader = rd

	// Record ktime offset for timestamp conversion
	s.ktimeOffsetNs = time.Now().UnixNano() - readKtimeNs()

	// Load auxiliary tracers (IO, sched — GVL not applicable in BPF mode
	// since there's no gem to fire GVL probes)
	if err := s.loadIOTracer(); err != nil {
		fmt.Fprintf(os.Stderr, "rbscope: io_tracer load skipped: %v\n", err)
	}
	if err := s.loadSchedTracer(); err != nil {
		fmt.Fprintf(os.Stderr, "rbscope: sched_tracer load skipped: %v\n", err)
	}

	// Attach perf_event to all CPUs
	if err := s.attachPerfEvents(); err != nil {
		s.Close() //nolint:errcheck
		return fmt.Errorf("attach perf events: %w", err)
	}

	return nil
}

// attachPerfEvents creates a perf_event on each CPU and attaches the BPF program.
func (s *StackWalkerBPF) attachPerfEvents() error {
	nCPU := runtime.NumCPU()

	for cpu := 0; cpu < nCPU; cpu++ {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: uint64(s.frequencyHz),
			Bits:   unix.PerfBitFreq,
		}

		fd, err := unix.PerfEventOpen(&attr, -1 /* all pids */, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("perf_event_open on cpu %d: %w", cpu, err)
		}
		s.perfFDs = append(s.perfFDs, fd)

		// Link BPF program to this perf event
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: s.objs.HandleRubySample,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err != nil {
			return fmt.Errorf("attach BPF to perf event on cpu %d: %w", cpu, err)
		}
		s.perfLinks = append(s.perfLinks, l)
	}

	fmt.Fprintf(os.Stderr, "rbscope: attached perf_event to %d CPUs at %d Hz\n", nCPU, s.frequencyHz)
	return nil
}

// AttachPID registers a Ruby process for stack walking.
// Discovers libruby, resolves EC address, writes to pid_configs BPF map.
func (s *StackWalkerBPF) AttachPID(pid uint32) error {
	// Find libruby in the process
	info, err := offsets.FindLibruby(pid)
	if err != nil {
		return fmt.Errorf("find libruby for pid %d: %w", pid, err)
	}
	fmt.Fprintf(os.Stderr, "rbscope: pid %d libruby at %s (base=0x%x)\n",
		pid, info.HostPath, info.BaseAddr)

	// Read EC address
	ec, err := offsets.ReadECAddress(pid, s.rubyOffsets, info.BaseAddr)
	if err != nil {
		return fmt.Errorf("read EC for pid %d: %w", pid, err)
	}
	fmt.Fprintf(os.Stderr, "rbscope: pid %d EC=0x%x\n", pid, ec)

	// Write to BPF map
	// pid_config struct: ec_addr(8) + libruby_base(8) = 16 bytes
	var cfg [16]byte
	binary.LittleEndian.PutUint64(cfg[0:8], ec)
	binary.LittleEndian.PutUint64(cfg[8:16], info.BaseAddr)
	if err := s.objs.PidConfigs.Put(pid, cfg); err != nil {
		return fmt.Errorf("write pid config for %d: %w", pid, err)
	}

	// Register with io_tracer
	if s.ioObjs != nil {
		val := uint8(1)
		if err := s.ioObjs.TargetPids.Put(pid, val); err != nil {
			fmt.Fprintf(os.Stderr, "rbscope: add pid %d to io target_pids: %v\n", pid, err)
		}
	}

	// Register with sched_tracer
	if s.schedObjs != nil {
		val := uint8(1)
		if err := s.schedObjs.TargetPids.Put(pid, val); err != nil {
			fmt.Fprintf(os.Stderr, "rbscope: add pid %d to sched target_pids: %v\n", pid, err)
		}
	}

	return nil
}

// DetachPID removes a PID from the stack walker.
func (s *StackWalkerBPF) DetachPID(pid uint32) error {
	if s.objs != nil {
		_ = s.objs.PidConfigs.Delete(pid)
	}
	if s.ioObjs != nil {
		_ = s.ioObjs.TargetPids.Delete(pid)
	}
	if s.schedObjs != nil {
		_ = s.schedObjs.TargetPids.Delete(pid)
	}
	return nil
}

// ReadRingBuffer reads from the stack walker + auxiliary ring buffers.
func (s *StackWalkerBPF) ReadRingBuffer(buf []byte) (int, error) {
	// Stack walker ring buffer has highest priority
	if s.reader != nil {
		s.reader.SetDeadline(time.Now().Add(1 * time.Millisecond))
		record, err := s.reader.Read()
		if err == nil {
			n := copy(buf, record.RawSample)
			return n, nil
		}
	}

	// Rotate between IO and sched (no GVL in BPF mode)
	s.readToggle = (s.readToggle + 1) % 2
	secondaries := []*ringbuf.Reader{s.ioReader, s.schedReader}
	for i := 0; i < 2; i++ {
		idx := (s.readToggle + i) % 2
		rd := secondaries[idx]
		if rd == nil {
			continue
		}
		rd.SetDeadline(time.Now().Add(5 * time.Millisecond))
		record, err := rd.Read()
		if err == nil {
			n := copy(buf, record.RawSample)
			return n, nil
		}
	}

	// Longer poll on stack walker to avoid busy-spinning
	if s.reader != nil {
		s.reader.SetDeadline(time.Now().Add(15 * time.Millisecond))
		record, err := s.reader.Read()
		if err == nil {
			n := copy(buf, record.RawSample)
			return n, nil
		}
	}

	return 0, fmt.Errorf("all ring buffers empty")
}

// KtimeOffsetNs returns the BPF ktime → wall clock offset.
func (s *StackWalkerBPF) KtimeOffsetNs() int64 {
	return s.ktimeOffsetNs
}

// Close releases all BPF resources.
func (s *StackWalkerBPF) Close() error {
	for _, l := range s.perfLinks {
		_ = l.Close()
	}
	for _, fd := range s.perfFDs {
		_ = unix.Close(fd)
	}
	for _, l := range s.ioLinks {
		_ = l.Close()
	}
	for _, l := range s.schedLinks {
		_ = l.Close()
	}
	if s.reader != nil {
		_ = s.reader.Close()
	}
	if s.ioReader != nil {
		_ = s.ioReader.Close()
	}
	if s.schedReader != nil {
		_ = s.schedReader.Close()
	}
	if s.objs != nil {
		_ = s.objs.Close()
	}
	if s.ioObjs != nil {
		_ = s.ioObjs.Close()
	}
	if s.schedObjs != nil {
		_ = s.schedObjs.Close()
	}
	return nil
}

// loadIOTracer loads the io_tracer BPF program (shared with gem mode).
func (s *StackWalkerBPF) loadIOTracer() error {
	ioObjs := &iotracerObjects{}
	if err := loadIotracerObjects(ioObjs, nil); err != nil {
		return fmt.Errorf("load io_tracer: %w", err)
	}
	s.ioObjs = ioObjs

	rd, err := ringbuf.NewReader(ioObjs.IoEvents)
	if err != nil {
		ioObjs.Close() //nolint:errcheck
		s.ioObjs = nil
		return fmt.Errorf("open io ring buffer: %w", err)
	}
	s.ioReader = rd

	// Attach syscall tracepoints (identical to RealBPF)
	type tpAttach struct {
		name string
		prog *ebpf.Program
	}
	tracepoints := []tpAttach{
		{"sys_enter_read", ioObjs.TpSysEnterRead},
		{"sys_exit_read", ioObjs.TpSysExitRead},
		{"sys_enter_write", ioObjs.TpSysEnterWrite},
		{"sys_exit_write", ioObjs.TpSysExitWrite},
		{"sys_enter_sendto", ioObjs.TpSysEnterSendto},
		{"sys_exit_sendto", ioObjs.TpSysExitSendto},
		{"sys_enter_recvfrom", ioObjs.TpSysEnterRecvfrom},
		{"sys_exit_recvfrom", ioObjs.TpSysExitRecvfrom},
		{"sys_enter_connect", ioObjs.TpSysEnterConnect},
		{"sys_exit_connect", ioObjs.TpSysExitConnect},
	}

	for _, tp := range tracepoints {
		l, err := link.Tracepoint("syscalls", tp.name, tp.prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint %s: %w", tp.name, err)
		}
		s.ioLinks = append(s.ioLinks, l)
	}

	return nil
}

// loadSchedTracer loads the sched_tracer for off-CPU / idle detection.
func (s *StackWalkerBPF) loadSchedTracer() error {
	schedObjs := &schedtracerObjects{}
	if err := loadSchedtracerObjects(schedObjs, nil); err != nil {
		return fmt.Errorf("load sched_tracer: %w", err)
	}
	s.schedObjs = schedObjs

	rd, err := ringbuf.NewReader(schedObjs.SchedEvents)
	if err != nil {
		schedObjs.Close() //nolint:errcheck
		s.schedObjs = nil
		return fmt.Errorf("open sched ring buffer: %w", err)
	}
	s.schedReader = rd

	l, err := link.Tracepoint("sched", "sched_switch", schedObjs.TpSchedSwitch, nil)
	if err != nil {
		rd.Close()        //nolint:errcheck
		schedObjs.Close() //nolint:errcheck
		s.schedObjs = nil
		s.schedReader = nil
		return fmt.Errorf("attach sched_switch tracepoint: %w", err)
	}
	s.schedLinks = append(s.schedLinks, l)

	return nil
}

// Offsets returns the DWARF-extracted Ruby offsets for frame resolution.
func (s *StackWalkerBPF) Offsets() *offsets.RubyOffsets {
	return s.rubyOffsets
}
