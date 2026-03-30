package offsets

import (
	"fmt"
	"os"
	"testing"
)

func TestReadECAddress(t *testing.T) {
	rubyPath := "/opt/ruby-4.0/lib/libruby.so.4.0.1"
	if _, err := os.Stat(rubyPath); err != nil {
		t.Skipf("not in Lima VM")
	}

	off, err := ExtractFromDWARF(rubyPath)
	if err != nil {
		t.Fatalf("ExtractFromDWARF: %v", err)
	}

	// Find a pitchfork worker PID — try multiple times since workers recycle
	var pid uint32
	var info *LibrubyInfo
	for attempt := 0; attempt < 3; attempt++ {
		pids := findPitchforkWorkers(t)
		if len(pids) == 0 {
			t.Skip("no pitchfork workers running")
		}
		pid = pids[0]
		info, err = FindLibruby(pid)
		if err == nil {
			break
		}
		t.Logf("attempt %d: FindLibruby(%d): %v, retrying...", attempt, pid, err)
	}
	if err != nil {
		t.Skipf("FindLibruby failed after retries (workers keep recycling): %v", err)
	}
	t.Logf("libruby: %s base=0x%x", info.HostPath, info.BaseAddr)

	ec, err := ReadECAddress(pid, off, info.BaseAddr)
	if err != nil {
		t.Fatalf("ReadECAddress(%d): %v", pid, err)
	}

	t.Logf("EC address: 0x%x", ec)
	if ec == 0 {
		t.Error("EC address is 0")
	}
	// EC should be in a reasonable address range
	if ec < 0x1000 || ec > 0xffffffffffff {
		t.Errorf("EC address 0x%x looks invalid", ec)
	}
}

func findPitchforkWorkers(t *testing.T) []uint32 {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		if contains(string(cmdline), "pitchfork") && contains(string(cmdline), "worker") {
			pids = append(pids, pid)
		}
	}
	return pids
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
