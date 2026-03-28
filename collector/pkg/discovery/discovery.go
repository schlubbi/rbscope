// Package discovery scans for Ruby processes and emits lifecycle events.
package discovery

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventKind distinguishes discovery events.
type EventKind int

const (
	// PIDFound indicates a Ruby process was discovered.
	PIDFound EventKind = iota
	// PIDLost indicates a Ruby process has exited.
	PIDLost
)

// Event is emitted when a Ruby process appears or disappears.
type Event struct {
	Kind EventKind
	PID  uint32
	Cmd  string // short command line
}

// Discovery scans /proc for Ruby-related processes and emits events.
type Discovery struct {
	interval time.Duration
	log      *slog.Logger
	mu       sync.Mutex
	known    map[uint32]string // pid -> cmdline
}

// rubyProcessNames are substrings matched against /proc/<pid>/cmdline.
var rubyProcessNames = []string{"ruby", "puma", "unicorn", "pitchfork"}

// New creates a Discovery with the given scan interval.
func New(interval time.Duration, logger *slog.Logger) *Discovery {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Discovery{
		interval: interval,
		log:      logger,
		known:    make(map[uint32]string),
	}
}

// Watch scans /proc at the configured interval and sends events to ch.
// It blocks until ctx is cancelled.
func (d *Discovery) Watch(ctx context.Context, ch chan<- Event) error {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	// Perform an initial scan immediately.
	d.scan(ch)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			d.scan(ch)
		}
	}
}

func (d *Discovery) scan(ch chan<- Event) {
	current := d.findRubyPIDs()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Detect new PIDs.
	for pid, cmd := range current {
		if _, ok := d.known[pid]; !ok {
			d.log.Info("discovered ruby process", "pid", pid, "cmd", cmd)
			d.known[pid] = cmd
			ch <- Event{Kind: PIDFound, PID: pid, Cmd: cmd}
		}
	}

	// Detect lost PIDs.
	for pid, cmd := range d.known {
		if _, ok := current[pid]; !ok {
			d.log.Info("lost ruby process", "pid", pid, "cmd", cmd)
			delete(d.known, pid)
			ch <- Event{Kind: PIDLost, PID: pid, Cmd: cmd}
		}
	}
}

func (d *Discovery) findRubyPIDs() map[uint32]string {
	return scanProcForRuby("/proc")
}

// scanProcForRuby scans the given directory (typically /proc) for Ruby processes.
func scanProcForRuby(procPath string) map[uint32]string {
	result := make(map[uint32]string)

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		cmdData, err := os.ReadFile(filepath.Join(procPath, entry.Name(), "cmdline")) // #nosec G304 -- reads /proc
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(string(cmdData), "\x00", " ")
		if cmd == "" {
			continue
		}
		if isRubyProcess(cmd) {
			result[uint32(pid)] = cmd
		}
	}
	return result
}

func isRubyProcess(cmdline string) bool {
	lower := strings.ToLower(cmdline)
	for _, name := range rubyProcessNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}
