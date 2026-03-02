package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsRubyProcess(t *testing.T) {
	tests := []struct {
		cmdline string
		want    bool
	}{
		{"/usr/bin/ruby app.rb", true},
		{"/usr/local/bin/puma -C config/puma.rb", true},
		{"bundle exec unicorn -c config/unicorn.rb", true},
		{"/usr/bin/pitchfork", true},
		{"/usr/bin/python app.py", false},
		{"/usr/bin/node server.js", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isRubyProcess(tt.cmdline)
		if got != tt.want {
			t.Errorf("isRubyProcess(%q) = %v, want %v", tt.cmdline, got, tt.want)
		}
	}
}

func TestScanProc_MockFS(t *testing.T) {
	// Create a mock /proc directory structure
	procDir := t.TempDir()

	// Create a fake Ruby process: pid 1234
	pid1Dir := filepath.Join(procDir, "1234")
	if err := os.MkdirAll(pid1Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid1Dir, "cmdline"), []byte("/usr/bin/ruby\x00app.rb\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a fake non-Ruby process: pid 5678
	pid2Dir := filepath.Join(procDir, "5678")
	if err := os.MkdirAll(pid2Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid2Dir, "cmdline"), []byte("/usr/bin/python\x00app.py\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a non-PID directory (should be skipped)
	if err := os.MkdirAll(filepath.Join(procDir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	pids := scanProcForRuby(procDir)

	if len(pids) != 1 {
		t.Fatalf("expected 1 Ruby PID, got %d: %v", len(pids), pids)
	}
	if _, ok := pids[1234]; !ok {
		t.Errorf("expected PID 1234 in results, got %v", pids)
	}
}
