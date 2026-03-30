package offsets

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LibrubyInfo contains the location and load address of libruby in a process.
type LibrubyInfo struct {
	// ContainerPath is the path as seen inside the process's mount namespace.
	ContainerPath string
	// HostPath is the path accessible from the host (via /proc/pid/root).
	HostPath string
	// BaseAddr is the runtime base address where libruby is loaded.
	BaseAddr uint64
}

// FindLibruby scans /proc/{pid}/maps to locate libruby.so and its load address.
// Returns the library info or an error if libruby is not found.
func FindLibruby(pid uint32) (*LibrubyInfo, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath) // #nosec G304 -- path derived from PID
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", mapsPath, err)
	}
	defer func() { _ = f.Close() }()

	var info *LibrubyInfo

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		pathname := fields[len(fields)-1]
		base := filepath.Base(pathname)

		// Look for libruby shared library
		if !strings.HasPrefix(base, "libruby") || !strings.Contains(base, ".so") {
			continue
		}

		// Parse address range
		addrParts := strings.SplitN(fields[0], "-", 2)
		if len(addrParts) != 2 {
			continue
		}
		var startAddr uint64
		if _, err := fmt.Sscanf(addrParts[0], "%x", &startAddr); err != nil {
			continue
		}

		// Parse file offset
		var fileOffset uint64
		if _, err := fmt.Sscanf(fields[2], "%x", &fileOffset); err != nil {
			continue
		}

		// We want the first mapping (file offset 0) for the base address
		if info == nil || fileOffset == 0 {
			info = &LibrubyInfo{
				ContainerPath: pathname,
				HostPath:      fmt.Sprintf("/proc/%d/root%s", pid, pathname),
				BaseAddr:      startAddr - fileOffset,
			}
			if fileOffset == 0 {
				// Found the base mapping, stop looking
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", mapsPath, err)
	}

	if info == nil {
		return nil, fmt.Errorf("libruby not found in %s", mapsPath)
	}

	return info, nil
}

// ReadECAddress reads the Ruby execution context address for a process by
// reading the ruby_current_ec TLS variable via /proc/pid/mem.
//
// On arm64: TLS base is in tpidr_el0, readable from /proc/pid/syscall
// On x86_64: TLS base is in fs_base, also readable from /proc/pid/syscall
//
// For single-threaded Ruby processes (pitchfork/unicorn workers), the EC
// address is stable — it doesn't change after initialization.
func ReadECAddress(pid uint32, offsets *RubyOffsets, librubyBase uint64) (uint64, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath) // #nosec G304 -- path derived from PID
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer func() { _ = f.Close() }()

	// Step 1: Read ruby_current_vm_ptr value
	vmPtrRuntimeAddr := librubyBase + offsets.VMPtrSymAddr
	vmPtr, err := readPtr(f, vmPtrRuntimeAddr)
	if err != nil {
		return 0, fmt.Errorf("read ruby_current_vm_ptr at 0x%x: %w", vmPtrRuntimeAddr, err)
	}
	if vmPtr == 0 {
		return 0, fmt.Errorf("ruby_current_vm_ptr is NULL (Ruby VM not initialized?)")
	}

	// Step 2: Read main_thread from vm.ractor.main_thread (inline struct)
	mainThread, err := readPtr(f, vmPtr+uint64(offsets.VMRactorMainThread))
	if err != nil {
		return 0, fmt.Errorf("read vm.ractor.main_thread at 0x%x+%d: %w",
			vmPtr, offsets.VMRactorMainThread, err)
	}
	if mainThread == 0 {
		return 0, fmt.Errorf("vm.ractor.main_thread is NULL")
	}

	// Step 3: Read ec from thread struct
	ec, err := readPtr(f, mainThread+uint64(offsets.ThreadEC))
	if err != nil {
		return 0, fmt.Errorf("read thread.ec at 0x%x+%d: %w",
			mainThread, offsets.ThreadEC, err)
	}
	if ec == 0 {
		return 0, fmt.Errorf("thread.ec is NULL (thread not running?)")
	}

	return ec, nil
}

// readPtr reads an 8-byte pointer from the given address in a /proc/pid/mem file.
func readPtr(f *os.File, addr uint64) (uint64, error) {
	var buf [8]byte
	n, err := f.ReadAt(buf[:], int64(addr)) //nolint:gosec // process addresses are valid offsets
	if err != nil {
		return 0, fmt.Errorf("read at 0x%x: %w", addr, err)
	}
	if n != 8 {
		return 0, fmt.Errorf("short read at 0x%x: got %d bytes", addr, n)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
