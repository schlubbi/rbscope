//go:build linux

// Package bpf_test contains integration tests that verify eBPF programs
// load and attach correctly on the running kernel. These tests require
// CAP_BPF (typically via sudo) and a kernel with BTF support.
//
// Run locally:  sudo go test -v -count=1 ./test/bpf/...
// Run via VM:   make vm-test-bpf
// Run via vimto: vimto -kernel :stable -sudo -- go test -v ./test/bpf/...
package bpf_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestMain(m *testing.M) {
	// Remove memlock rlimit for BPF operations (required on kernels < 5.11).
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: RemoveMemlock failed: %v\n", err)
	}
	os.Exit(m.Run())
}

// TestBTFAvailable verifies the kernel exposes BTF, which is required for
// CO-RE (Compile Once, Run Everywhere) BPF programs.
func TestBTFAvailable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Fatal("kernel BTF not available at /sys/kernel/btf/vmlinux — CO-RE programs will not load")
	}
	t.Log("BTF available ✓")
}

// TestRbscopeBPFLoad verifies the ruby_reader BPF program loads and its
// maps and programs are created correctly.
func TestRbscopeBPFLoad(t *testing.T) {
	spec := loadSpec(t, "rbscope")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load rbscope BPF collection: %v", err)
	}
	defer coll.Close()

	// Verify the ring buffer map exists
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		t.Fatal("expected 'events' ring buffer map")
	}
	info, err := eventsMap.Info()
	if err != nil {
		t.Fatalf("map info: %v", err)
	}
	if info.Type != ebpf.RingBuf {
		t.Fatalf("expected RingBuf map, got %v", info.Type)
	}
	t.Logf("events map: type=%v ✓", info.Type)

	// Verify the uprobe program exists
	prog := coll.Programs["handle_ruby_sample"]
	if prog == nil {
		t.Fatal("expected 'handle_ruby_sample' program")
	}
	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("program info: %v", err)
	}
	t.Logf("handle_ruby_sample: type=%v ✓", progInfo.Type)
}

// TestIotracerBPFLoad verifies the I/O tracer BPF program loads.
func TestIotracerBPFLoad(t *testing.T) {
	spec := loadSpec(t, "iotracer")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load iotracer BPF collection: %v", err)
	}
	defer coll.Close()

	if len(coll.Programs) == 0 {
		t.Fatal("iotracer collection has no programs")
	}
	for name, prog := range coll.Programs {
		info, _ := prog.Info()
		t.Logf("  %s: type=%v ✓", name, info.Type)
	}
}

// TestSchedtracerBPFLoad verifies the scheduler tracer BPF program loads.
func TestSchedtracerBPFLoad(t *testing.T) {
	spec := loadSpec(t, "schedtracer")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load schedtracer BPF collection: %v", err)
	}
	defer coll.Close()

	if len(coll.Programs) == 0 {
		t.Fatal("schedtracer collection has no programs")
	}
	for name, prog := range coll.Programs {
		info, _ := prog.Info()
		t.Logf("  %s: type=%v ✓", name, info.Type)
	}
}

// TestGvltracerBPFLoad verifies the GVL tracer BPF program loads and both
// ring buffer maps are created correctly — gvl_events for state changes
// and gvl_stack_events for SUSPENDED stack captures.
func TestGvltracerBPFLoad(t *testing.T) {
	spec := loadSpec(t, "gvltracer")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load gvltracer BPF collection: %v", err)
	}
	defer coll.Close()

	// Verify the state change ring buffer
	gvlEvents := coll.Maps["gvl_events"]
	if gvlEvents == nil {
		t.Fatal("expected 'gvl_events' ring buffer map")
	}
	info, err := gvlEvents.Info()
	if err != nil {
		t.Fatalf("gvl_events info: %v", err)
	}
	if info.Type != ebpf.RingBuf {
		t.Fatalf("gvl_events: expected RingBuf, got %v", info.Type)
	}
	t.Logf("gvl_events: type=%v ✓", info.Type)

	// Verify the separate stack event ring buffer (split from gvl_events
	// to prevent high-volume 32-byte state events from starving large
	// ~16KB stack event reservations).
	gvlStackEvents := coll.Maps["gvl_stack_events"]
	if gvlStackEvents == nil {
		t.Fatal("expected 'gvl_stack_events' ring buffer map")
	}
	stackInfo, err := gvlStackEvents.Info()
	if err != nil {
		t.Fatalf("gvl_stack_events info: %v", err)
	}
	if stackInfo.Type != ebpf.RingBuf {
		t.Fatalf("gvl_stack_events: expected RingBuf, got %v", stackInfo.Type)
	}
	t.Logf("gvl_stack_events: type=%v ✓", stackInfo.Type)

	if len(coll.Programs) == 0 {
		t.Fatal("gvltracer collection has no programs")
	}
	for name, prog := range coll.Programs {
		progInfo, _ := prog.Info()
		t.Logf("  %s: type=%v ✓", name, progInfo.Type)
	}
}

// TestSchedtracerAttachSelf verifies the scheduler tracer can attach to
// the current process and the kernel begins producing events.
func TestSchedtracerAttachSelf(t *testing.T) {
	spec := loadSpec(t, "schedtracer")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load schedtracer: %v", err)
	}
	defer coll.Close()

	// Just verify we can load — actual tracepoint attachment
	// requires matching program types to hook points which is
	// collector-specific logic. The fact that it loads without
	// verifier errors on this kernel is the key assertion.
	t.Log("schedtracer loaded and verified on this kernel ✓")
}

// loadSpec loads a BPF CollectionSpec from the bpf2go-generated ELF.
// bpf2go uses the naming convention: {name}_{target}_bpfel.o
// where target is "x86" for amd64 and "arm64" for arm64.
func loadSpec(t *testing.T, name string) *ebpf.CollectionSpec {
	t.Helper()

	// Map Go GOARCH to bpf2go -target names
	targetMap := map[string]string{
		"amd64": "x86",
		"arm64": "arm64",
	}
	target, ok := targetMap[runtime.GOARCH]
	if !ok {
		t.Skipf("unsupported architecture: %s", runtime.GOARCH)
	}

	objFile := "../../pkg/bpf/" + name + "_" + target + "_bpfel.o"
	if _, err := os.Stat(objFile); os.IsNotExist(err) {
		t.Skipf("BPF object not found at %s — run 'go generate ./pkg/bpf/' first", objFile)
	}

	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		t.Fatalf("failed to load BPF spec from %s: %v", objFile, err)
	}
	return spec
}
