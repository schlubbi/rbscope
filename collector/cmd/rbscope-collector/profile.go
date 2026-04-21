package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/schlubbi/rbscope/collector/pkg/bpf"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
	csvexport "github.com/schlubbi/rbscope/collector/pkg/export/csv"
	"github.com/schlubbi/rbscope/collector/pkg/export/gecko"
	"github.com/schlubbi/rbscope/collector/pkg/offsets"
	"github.com/schlubbi/rbscope/collector/pkg/symbols"
	"github.com/schlubbi/rbscope/collector/pkg/timeline"
)

// profile flags
var (
	flagProfileOutput    string
	flagProfileFormat    string
	flagProfileMode      string
	flagProfileRubyPath  string
	flagProfilePprof     string
	flagProfileNativeAll bool
	flagProfileDuration  time.Duration
)

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile [flags] -- <command> [args...]",
		Short: "Launch a Ruby process and profile it",
		Long: `Profile a Ruby process from start to finish.

Examples:
  rbscope-collector profile -- ruby my_script.rb
  rbscope-collector profile -- bin/rails test test/models/user_test.rb
  rbscope-collector profile --mode combined -- bundle exec rspec spec/
  rbscope-collector profile --duration 30s -- bin/rails server
  rbscope-collector profile --native-all -o profile.json -- ruby bench.rb`,
		DisableFlagParsing: false,
		RunE:               runProfile,
		// Everything after -- is the target command.
		Args: cobra.ArbitraryArgs,
	}

	f := cmd.Flags()
	f.StringVarP(&flagProfileOutput, "output", "o", "", "Output file path (default: rbscope-<cmd>-<timestamp>.json)")
	f.StringVar(&flagProfileFormat, "format", "gecko", "Output format: gecko, csv, pb")
	f.StringVar(&flagProfileMode, "mode", "bpf", "Profiling mode: bpf (default), combined, or gem")
	f.StringVar(&flagProfileRubyPath, "ruby-path", "", "Path to ruby binary or libruby.so with DWARF (auto-detected if omitted)")
	f.StringVar(&flagProfilePprof, "pprof", "", "Write Go CPU profile to this file")
	f.BoolVar(&flagProfileNativeAll, "native-all", false, "Include Ruby VM native frames (libruby internals)")
	f.DurationVar(&flagProfileDuration, "duration", 0, "Max capture duration (0 = until process exits)")

	return cmd
}

func runProfile(_ *cobra.Command, args []string) error {
	// Everything after "--" ends up in args.
	if len(args) == 0 {
		return fmt.Errorf("no command specified. Usage: rbscope-collector profile -- <command> [args...]")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// --- Start the child process ---
	child := exec.Command(args[0], args[1:]...) //nolint:gosec // G204: user-provided command is intentional
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Start(); err != nil {
		return fmt.Errorf("start command %q: %w", args[0], err)
	}
	childPID := uint32(child.Process.Pid) //nolint:gosec // G115: PID is always small positive
	logger.Info("child started", "pid", childPID, "command", args)

	// Channel to receive child exit.
	childDone := make(chan error, 1)
	go func() {
		childDone <- child.Wait()
	}()

	// --- Detect Ruby path ---
	rubyPath := flagProfileRubyPath
	if rubyPath == "" && flagProfileMode != "gem" {
		var err error
		rubyPath, err = detectRubyPath(childPID, logger)
		if err != nil {
			// Kill the child — we can't profile without the ruby path.
			_ = child.Process.Kill()
			<-childDone
			return fmt.Errorf("detect ruby path: %w\nUse --ruby-path to specify it manually", err)
		}
	}

	// --- Default output filename ---
	output := flagProfileOutput
	if output == "" {
		cmdBase := filepath.Base(args[0])
		output = fmt.Sprintf("rbscope-%s-%s.json", cmdBase, time.Now().Format("20060102-150405"))
	}

	// --- Set up timeline builder ---
	var tb *timeline.Builder
	switch flagProfileFormat {
	case "gecko", "csv":
		hostname, _ := os.Hostname()
		tb = timeline.NewBuilder("profile", hostname, childPID, 99)
		tb.SetNativeAll(flagProfileNativeAll)
		if resolver, err := symbols.NewResolver(childPID); err == nil {
			tb.SetResolver(resolver)
		}
	case "pb":
		// pb format uses direct exporters, not timeline builder
	default:
		_ = child.Process.Kill()
		<-childDone
		return fmt.Errorf("unknown format: %q (use gecko, csv, or pb)", flagProfileFormat)
	}

	// --- Set up BPF program ---
	var exporters []collector.Exporter
	if tb != nil {
		exporters = append(exporters, &timelineExporter{builder: tb})
	}

	cfg := collector.Config{
		FrequencyHz: 99,
		Exporters:   exporters,
		Logger:      logger,
	}

	var bpfProg collector.BPFProgram
	var sw *bpf.StackWalkerBPF

	switch flagProfileMode {
	case "bpf":
		var err error
		sw, err = bpf.NewStackWalkerBPF(rubyPath, 99)
		if err != nil {
			_ = child.Process.Kill()
			<-childDone
			return fmt.Errorf("create stack walker: %w", err)
		}
		bpfProg = sw
		if tb != nil {
			tb.SetFrameResolver(offsets.NewFrameResolver(sw.Offsets()))
		}

	case "combined":
		combined, err := bpf.NewCombinedBPF("", rubyPath, 99)
		if err != nil {
			_ = child.Process.Kill()
			<-childDone
			return fmt.Errorf("create combined BPF: %w", err)
		}
		bpfProg = combined
		sw = combined.Walker()
		if tb != nil {
			tb.SetFrameResolver(offsets.NewFrameResolver(sw.Offsets()))
		}
		logger.Info("combined mode: BPF CPU sampling + gem alloc/GVL tracking")

	case "gem":
		realBPF, err := bpf.NewRealBPF("")
		if err != nil {
			_ = child.Process.Kill()
			<-childDone
			return fmt.Errorf("create BPF program: %w", err)
		}
		bpfProg = realBPF
		// Set up frame resolver if ruby path available
		if tb != nil && rubyPath != "" {
			if rubyOffsets, err := offsets.ExtractFromDWARF(rubyPath); err == nil {
				if info, err := offsets.FindLibruby(childPID); err == nil {
					rubyOffsets.VMPtrSymAddr += info.BaseAddr
					rubyOffsets.GlobalSymbolsAddr += info.BaseAddr
				}
				tb.SetFrameResolver(offsets.NewFrameResolver(rubyOffsets))
			}
		}

	default:
		_ = child.Process.Kill()
		<-childDone
		return fmt.Errorf("unknown mode: %q (use bpf, combined, or gem)", flagProfileMode)
	}

	// --- Start collector and attach ---
	c := collector.New(cfg, bpfProg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		_ = child.Process.Kill()
		<-childDone
		return fmt.Errorf("start collector: %w", err)
	}

	// PID namespace setup
	if tb != nil && sw == nil {
		// Gem mode
		hostPID, err := bpf.DiscoverHostPID(childPID)
		if err == nil && hostPID != childPID {
			tb.SetHostToContainerPID(hostPID, childPID)
		}
	}
	if tb != nil {
		ppid := readPPID(childPID)
		tb.SetPIDDiscoverer(func(hostPID uint32) (uint32, bool) {
			return findContainerPIDForHost(hostPID, ppid)
		})
	}

	if err := c.AttachPID(childPID); err != nil {
		_ = child.Process.Kill()
		<-childDone
		return fmt.Errorf("attach to pid %d: %w", childPID, err)
	}

	// BPF mode: register PID mappings
	if tb != nil && sw != nil {
		for containerPID, hostPID := range sw.PIDMapping() {
			tb.SetHostToContainerPID(hostPID, containerPID)
		}
	}

	// Attach siblings (Pitchfork/Puma workers)
	attachSiblingPIDs(c, childPID, logger, tb)

	logger.Info("profiling started", "pid", childPID, "mode", flagProfileMode, "output", output)

	// --- pprof ---
	if flagProfilePprof != "" {
		pprofFile, err := os.Create(flagProfilePprof) //nolint:gosec // G304: user-provided path
		if err != nil {
			return fmt.Errorf("create pprof file: %w", err)
		}
		defer func() { _ = pprofFile.Close() }()
		if err := pprof.StartCPUProfile(pprofFile); err != nil {
			return fmt.Errorf("start pprof: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	// --- Signal handling ---
	// First Ctrl-C: forward SIGINT to child, wait for exit.
	// Second Ctrl-C: force kill child.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// --- Wait for child exit or duration cap ---
	var durationTimer *time.Timer
	var durationCh <-chan time.Time
	if flagProfileDuration > 0 {
		durationTimer = time.NewTimer(flagProfileDuration)
		durationCh = durationTimer.C
		defer durationTimer.Stop()
	}

	var childErr error
	select {
	case childErr = <-childDone:
		logger.Info("child exited")
	case <-durationCh:
		logger.Info("duration cap reached, stopping capture")
		// Don't kill the child — just stop profiling
	case sig := <-sigCh:
		logger.Info("signal received, forwarding to child", "signal", sig)
		_ = child.Process.Signal(sig)
		// Wait for child or second signal
		select {
		case childErr = <-childDone:
			logger.Info("child exited after signal")
		case <-sigCh:
			logger.Info("second signal, force killing child")
			_ = child.Process.Kill()
			childErr = <-childDone
		}
	}

	// --- Stop collector and export ---
	_ = c.Stop()

	if tb != nil {
		for tid, count := range tb.SampleCounts() {
			if count > 0 {
				logger.Info("samples collected", "tid", tid, "count", count)
			}
		}

		capture := tb.Build()
		tb.CloseFrameResolver()

		switch flagProfileFormat {
		case "gecko":
			if err := gecko.Export(capture, output); err != nil {
				return fmt.Errorf("export gecko profile: %w", err)
			}
			logger.Info("profile exported", "output", output, "format", "gecko")
		case "csv":
			if err := csvexport.Export(capture, output); err != nil {
				return fmt.Errorf("export csv: %w", err)
			}
			logger.Info("profile exported", "output", output, "format", "csv")
		}
	}

	// Propagate child exit code.
	if childErr != nil {
		if exitErr, ok := childErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("child process error: %w", childErr)
	}
	return nil
}

// detectRubyPath finds the Ruby interpreter for a running process.
// It checks /proc/<pid>/exe first, then polls /proc/<pid>/maps for libruby.
func detectRubyPath(pid uint32, logger *slog.Logger) (string, error) {
	// Strategy 1: /proc/pid/exe — works when ruby is the main binary
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		base := filepath.Base(exePath)
		if strings.HasPrefix(base, "ruby") {
			logger.Info("detected ruby from /proc/pid/exe", "path", exePath)
			return exePath, nil
		}
	}

	// Strategy 2: poll /proc/pid/maps for libruby or ruby binary.
	// The child may still be loading (shell wrapper → exec → ruby).
	// Poll for up to 5 seconds.
	logger.Info("waiting for Ruby to appear in /proc/pid/maps...", "pid", pid)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		path, found := findRubyInMaps(pid)
		if found {
			logger.Info("detected ruby from /proc/pid/maps", "path", path)
			return path, nil
		}
		time.Sleep(100 * time.Millisecond)

		// Re-check /proc/pid/exe — the process may have exec'd from a shell wrapper.
		exePath, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err == nil {
			base := filepath.Base(exePath)
			if strings.HasPrefix(base, "ruby") {
				logger.Info("detected ruby from /proc/pid/exe (after exec)", "path", exePath)
				return exePath, nil
			}
		}
	}

	// Strategy 3: try the offsets package's existing discovery
	info, err := offsets.FindLibruby(pid)
	if err == nil {
		logger.Info("detected ruby via FindLibruby", "path", info.HostPath)
		return info.HostPath, nil
	}

	return "", fmt.Errorf("could not detect Ruby interpreter for pid %d after 5s", pid)
}

// findRubyInMaps scans /proc/<pid>/maps for libruby.so or a ruby binary mapping.
func findRubyInMaps(pid uint32) (string, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Maps lines look like:
		// 7f1234560000-7f1234570000 r-xp 00000000 08:01 123456 /usr/lib/libruby.so.3.2
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		base := filepath.Base(path)

		// Match libruby.so variants
		if strings.HasPrefix(base, "libruby") && strings.Contains(base, ".so") {
			return path, true
		}
		// Match ruby binary (statically linked)
		if base == "ruby" || strings.HasPrefix(base, "ruby-") {
			return path, true
		}
	}
	return "", false
}
