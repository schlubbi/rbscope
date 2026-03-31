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
	"github.com/cilium/ebpf/asm"
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
	perfFDs       []int       // perf_event file descriptors (one per CPU)
	perfLinks     []link.Link // perf_event → BPF program links
	rubyOffsets   *offsets.RubyOffsets
	ktimeOffsetNs int64
	frequencyHz   int
	// IO/GVL/sched tracers (shared with gem mode)
	ioObjs      *iotracerObjects
	ioReader    *ringbuf.Reader
	ioLinks     []link.Link
	schedObjs   *schedtracerObjects
	schedReader *ringbuf.Reader
	schedLinks  []link.Link
	readToggle  int
	// pidMapping tracks container PID → host PID for namespace support
	pidMapping  map[uint32]uint32
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
			Sample: uint64(s.frequencyHz), //nolint:gosec // frequencyHz is always small positive (e.g. 99)
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

	// Write to BPF map.
	// In containerized environments, bpf_get_current_pid_tgid() returns the
	// host-namespace PID, not the container PID. Discover the host PID so the
	// BPF map lookup matches correctly.
	mapKey, err := DiscoverHostPID(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rbscope: host PID discovery failed, using container PID: %v\n", err)
		mapKey = pid
	}

	// Cache the mapping for DetachPID
	if s.pidMapping == nil {
		s.pidMapping = make(map[uint32]uint32)
	}
	s.pidMapping[pid] = mapKey

	// pid_config struct: ec_addr(8) + libruby_base(8) = 16 bytes
	var cfg [16]byte
	binary.LittleEndian.PutUint64(cfg[0:8], ec)
	binary.LittleEndian.PutUint64(cfg[8:16], info.BaseAddr)
	if err := s.objs.PidConfigs.Put(mapKey, cfg); err != nil {
		return fmt.Errorf("write pid config for %d: %w", mapKey, err)
	}

	// Register with io_tracer — must use host PID because io_tracer.c
	// checks bpf_get_current_pid_tgid() which returns host-namespace PIDs.
	if s.ioObjs != nil {
		val := uint8(1)
		if err := s.ioObjs.TargetPids.Put(mapKey, val); err != nil {
			fmt.Fprintf(os.Stderr, "rbscope: add pid %d to io target_pids: %v\n", mapKey, err)
		}
	}

	// Adjust GlobalSymbolsAddr to runtime address (one-time, first PID)
	if s.rubyOffsets.GlobalSymbolsAddr != 0 && s.rubyOffsets.GlobalSymbolsAddr < info.BaseAddr {
		s.rubyOffsets.GlobalSymbolsAddr += info.BaseAddr
	}

	// Register with sched_tracer — same host PID requirement.
	if s.schedObjs != nil {
		val := uint8(1)
		if err := s.schedObjs.TargetPids.Put(mapKey, val); err != nil {
			fmt.Fprintf(os.Stderr, "rbscope: add pid %d to sched target_pids: %v\n", mapKey, err)
		}
	}

	return nil
}

// DetachPID removes a PID from the stack walker.
func (s *StackWalkerBPF) DetachPID(pid uint32) error {
	// Use the host PID (which may differ from container PID in namespaced environments)
	mapKey := pid
	if s.pidMapping != nil {
		if hostPid, ok := s.pidMapping[pid]; ok {
			mapKey = hostPid
			delete(s.pidMapping, pid)
		}
	}
	if s.objs != nil {
		_ = s.objs.PidConfigs.Delete(mapKey)
	}
	if s.ioObjs != nil {
		_ = s.ioObjs.TargetPids.Delete(mapKey)
	}
	if s.schedObjs != nil {
		_ = s.schedObjs.TargetPids.Delete(mapKey)
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

// PIDMapping returns the container→host PID mappings discovered during
// AttachPID. Callers can invert this to translate host PIDs in BPF events
// back to container PIDs for /proc access.
func (s *StackWalkerBPF) PIDMapping() map[uint32]uint32 {
	return s.pidMapping
}

// DiscoverHostPID returns the init-namespace (host) PID for a given container PID.
//
// In containerized environments (Docker, Codespaces, etc.), bpf_get_current_pid_tgid()
// returns the host-namespace PID, which may differ from the PID seen inside the
// container. This function discovers the mapping by attaching a minimal BPF program
// (via inline assembly) to a PID-targeted perf event and reading what
// bpf_get_current_pid_tgid() returns.
//
// perf_event_open() with a specific pid handles namespace translation internally,
// so the event fires for the correct task. The BPF helper then returns the
// init-namespace PID which is what the main stack walker BPF will see.
func DiscoverHostPID(containerPid uint32) (uint32, error) {
	// Create a small array map to receive the result from BPF
	resultMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		return containerPid, fmt.Errorf("create discovery map: %w", err)
	}
	defer resultMap.Close()

	// Minimal BPF program: call bpf_get_current_pid_tgid(), store to map
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.PerfEvent,
		Instructions: asm.Instructions{
			asm.FnGetCurrentPidTgid.Call(),
			asm.Mov.Reg(asm.R6, asm.R0),
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.StoreMem(asm.RFP, -16, asm.R6, asm.DWord),
			asm.LoadMapPtr(asm.R1, resultMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -16),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return containerPid, fmt.Errorf("load discovery prog: %w", err)
	}
	defer prog.Close()

	// Attach perf events targeted at containerPid on all CPUs.
	nCPU := runtime.NumCPU()
	var discoveryLinks []link.Link
	var discoveryFDs []int
	for cpu := 0; cpu < nCPU; cpu++ {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 999,
			Bits:   unix.PerfBitFreq,
		}
		fd, err := unix.PerfEventOpen(&attr, int(containerPid), cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			continue
		}
		discoveryFDs = append(discoveryFDs, fd)
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: prog,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err != nil {
			unix.Close(fd)
			continue
		}
		discoveryLinks = append(discoveryLinks, l)
	}
	defer func() {
		for _, l := range discoveryLinks {
			l.Close()
		}
		for _, fd := range discoveryFDs {
			unix.Close(fd)
		}
	}()

	if len(discoveryLinks) == 0 {
		return containerPid, nil
	}

	// Poll until the target gets scheduled and sampled.
	// Workers may be idle between requests, so retry a few times.
	var hostPid uint32
	for attempt := 0; attempt < 10; attempt++ {
		time.Sleep(200 * time.Millisecond)

		var key uint32
		var val uint64
		if err := resultMap.Lookup(key, &val); err != nil {
			continue
		}

		hostPid = uint32(val >> 32)
		if hostPid != 0 {
			break
		}
	}

	if hostPid != 0 && hostPid != containerPid {
		fmt.Fprintf(os.Stderr, "rbscope: PID namespace detected: container PID %d -> host PID %d\n",
			containerPid, hostPid)
		return hostPid, nil
	}

	return containerPid, nil
}
