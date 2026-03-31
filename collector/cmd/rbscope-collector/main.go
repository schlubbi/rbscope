// Package main provides the rbscope-collector CLI.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/schlubbi/rbscope/collector/internal"
	"github.com/schlubbi/rbscope/collector/pkg/bpf"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
	"github.com/schlubbi/rbscope/collector/pkg/discovery"
	"github.com/schlubbi/rbscope/collector/pkg/export"
	csvexport "github.com/schlubbi/rbscope/collector/pkg/export/csv"
	"github.com/schlubbi/rbscope/collector/pkg/export/gecko"
	"github.com/schlubbi/rbscope/collector/pkg/offsets"
	"github.com/schlubbi/rbscope/collector/pkg/symbols"
	"github.com/schlubbi/rbscope/collector/pkg/timeline"
)

// run flags
var (
	flagPID          uint32
	flagFrequency    int
	flagExport       string
	flagPyroscopeURL string
	flagDatadogURL   string
	flagOTLPEndpoint string
	flagOutputDir    string
	flagHealthPort   int
	flagBPFObj       string
)

// capture flags
var (
	flagCapturePID      uint32
	flagCaptureDuration time.Duration
	flagCaptureOutput   string
	flagCaptureBPFObj   string
	flagCaptureFormat   string
	flagCaptureMode     string
	flagCaptureRubyPath string
)

func main() {
	root := &cobra.Command{
		Use:   "rbscope-collector",
		Short: "eBPF-based Ruby profiling collector",
	}

	root.AddCommand(runCmd(), captureCmd(), demoCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the collector (default)",
		RunE:  runCollector,
	}

	f := cmd.Flags()
	f.Uint32Var(&flagPID, "pid", 0, "Target PID (0 = auto-discover Ruby processes)")
	f.IntVar(&flagFrequency, "frequency", 19, "Sampling frequency in Hz")
	f.StringVar(&flagExport, "export", "file", "Comma-separated exporters: pyroscope,datadog,otlp,file")
	f.StringVar(&flagPyroscopeURL, "pyroscope-url", "http://localhost:4040", "Pyroscope server URL")
	f.StringVar(&flagDatadogURL, "datadog-url", "", "Datadog agent URL")
	f.StringVar(&flagOTLPEndpoint, "otlp-endpoint", "", "OTLP gRPC endpoint")
	f.StringVar(&flagOutputDir, "output-dir", "./profiles", "Output directory for file exporter")
	f.IntVar(&flagHealthPort, "health-port", 8080, "Health/metrics HTTP port")
	f.StringVar(&flagBPFObj, "bpf-obj", "", "Path to compiled BPF ELF object (e.g. ruby_reader.o)")

	return cmd
}

func captureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "On-demand deep capture of a single process",
		RunE:  runCapture,
	}

	f := cmd.Flags()
	f.Uint32Var(&flagCapturePID, "pid", 0, "Target PID (required)")
	f.DurationVar(&flagCaptureDuration, "duration", 10*time.Second, "Capture duration")
	f.StringVar(&flagCaptureOutput, "output", "capture.pb", "Output file path")
	f.StringVar(&flagCaptureFormat, "format", "pb", "Output format: pb (protobuf), gecko (Firefox Profiler JSON), or csv (DuckDB-ready)")
	f.StringVar(&flagCaptureBPFObj, "bpf-obj", "", "Path to compiled BPF ELF object")
	f.StringVar(&flagCaptureMode, "mode", "gem", "Profiling mode: gem (USDT probes) or bpf (zero-instrumentation)")
	f.StringVar(&flagCaptureRubyPath, "ruby-path", "", "Path to libruby.so with DWARF (required for --mode=bpf)")
	_ = cmd.MarkFlagRequired("pid")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("rbscope-collector %s (commit: %s, built: %s)\n",
				internal.Version, internal.GitCommit, internal.BuildDate)
		},
	}
}

func runCollector(_ *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	exporters, err := buildExporters(logger)
	if err != nil {
		return err
	}

	cfg := collector.Config{
		FrequencyHz: flagFrequency,
		Exporters:   exporters,
		Logger:      logger,
	}

	// Load BPF program — use embedded bytecode by default, or --bpf-obj if specified.
	var bpfProg collector.BPFProgram
	realBPF, err := bpf.NewRealBPF(flagBPFObj)
	if err != nil {
		return fmt.Errorf("create BPF program: %w", err)
	}
	bpfProg = realBPF

	c := collector.New(cfg, bpfProg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start health/metrics server.
	go serveHealth(ctx, logger)

	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("start collector: %w", err)
	}
	defer func() { _ = c.Stop() }()

	if flagPID != 0 {
		if err := c.AttachPID(flagPID); err != nil {
			return err
		}
	} else {
		// Auto-discover Ruby processes.
		disc := discovery.New(5*time.Second, logger)
		events := make(chan discovery.Event, 64)
		go func() {
			_ = disc.Watch(ctx, events)
		}()
		go func() {
			for ev := range events {
				switch ev.Kind {
				case discovery.PIDFound:
					if err := c.AttachPID(ev.PID); err != nil {
						logger.Warn("attach failed", "pid", ev.PID, "err", err)
					}
				case discovery.PIDLost:
					if err := c.DetachPID(ev.PID); err != nil {
						logger.Warn("detach failed", "pid", ev.PID, "err", err)
					}
				}
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutting down")
	return nil
}

func runCapture(_ *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var exporters []collector.Exporter
	var tb *timeline.Builder

	switch flagCaptureFormat {
	case "gecko", "csv":
		// Both formats: accumulate into timeline builder, export at end.
		hostname, _ := os.Hostname()
		tb = timeline.NewBuilder("capture", hostname, flagCapturePID, 99)
		// Set up symbol resolver for native stack resolution
		if resolver, err := symbols.NewResolver(flagCapturePID); err == nil {
			tb.SetResolver(resolver)
			logger.Info("native stack resolution enabled", "pid", flagCapturePID)
		} else {
			logger.Warn("native stack resolution unavailable", "pid", flagCapturePID, "err", err)
		}
		exporters = append(exporters, &timelineExporter{builder: tb})
	case "pb":
		fe, err := export.NewFileExporter(flagCaptureOutput)
		if err != nil {
			return err
		}
		defer func() { _ = fe.Close() }()
		exporters = append(exporters, fe)
	default:
		return fmt.Errorf("unknown format: %q (use pb, gecko, or csv)", flagCaptureFormat)
	}

	cfg := collector.Config{
		FrequencyHz: 99, // higher frequency for captures
		Exporters:   exporters,
		Logger:      logger,
	}

	var bpfProg collector.BPFProgram
	var sw *bpf.StackWalkerBPF // hoisted for post-AttachPID PID mapping
	switch flagCaptureMode {
	case "gem":
		realBPF, err := bpf.NewRealBPF(flagCaptureBPFObj)
		if err != nil {
			return fmt.Errorf("create BPF program: %w", err)
		}
		bpfProg = realBPF

		// Set up frame resolver for v3 alloc stack data (raw frame VALUEs).
		// Discover libruby and extract DWARF offsets, same as BPF mode.
		if tb != nil {
			rubyPath := flagCaptureRubyPath
			if rubyPath == "" {
				info, err := offsets.FindLibruby(flagCapturePID)
				if err == nil {
					rubyPath = info.HostPath
				}
			}
			if rubyPath != "" {
				rubyOffsets, err := offsets.ExtractFromDWARF(rubyPath)
				if err == nil {
					// Adjust symbol addresses to runtime addresses
					info, err := offsets.FindLibruby(flagCapturePID)
					if err == nil {
						rubyOffsets.VMPtrSymAddr += info.BaseAddr
						rubyOffsets.GlobalSymbolsAddr += info.BaseAddr
					}
					tb.SetFrameResolver(offsets.NewFrameResolver(rubyOffsets))
					logger.Info("frame resolver ready for gem mode alloc tracking", "ruby", rubyPath)
				} else {
					logger.Warn("could not extract Ruby offsets for alloc frame resolution", "err", err)
				}
			}
		}
	case "bpf":
		rubyPath := flagCaptureRubyPath
		if rubyPath == "" {
			// Auto-discover from /proc/pid/maps
			info, err := offsets.FindLibruby(flagCapturePID)
			if err != nil {
				return fmt.Errorf("auto-discover libruby for pid %d: %w (use --ruby-path)", flagCapturePID, err)
			}
			rubyPath = info.HostPath
			logger.Info("auto-discovered libruby", "path", rubyPath)
		}
		var err error
		sw, err = bpf.NewStackWalkerBPF(rubyPath, 99)
		if err != nil {
			return fmt.Errorf("create stack walker: %w", err)
		}
		bpfProg = sw
		// Set up frame resolver for BPF stack walker iseq → method resolution
		if tb != nil {
			tb.SetFrameResolver(offsets.NewFrameResolver(sw.Offsets()))
		}
	default:
		return fmt.Errorf("unknown mode: %q (use gem or bpf)", flagCaptureMode)
	}

	c := collector.New(cfg, bpfProg)

	ctx, cancel := context.WithTimeout(context.Background(), flagCaptureDuration)
	defer cancel()

	if err := c.Start(ctx); err != nil {
		return err
	}
	defer func() { _ = c.Stop() }()

	if err := c.AttachPID(flagCapturePID); err != nil {
		return err
	}

	// Register PID namespace mappings (must happen after AttachPID which
	// discovers the host PID) so the frame resolver reads /proc/<containerPID>/mem.
	if tb != nil && sw != nil {
		for containerPID, hostPID := range sw.PIDMapping() {
			tb.SetHostToContainerPID(hostPID, containerPID)
		}
	}

	// Also add sibling processes to the I/O tracer's target_pids map.
	// Pitchfork forks worker processes that inherit the uprobe but have
	// different PIDs. The I/O tracepoints need all PIDs in the filter.
	attachSiblingPIDs(c, flagCapturePID, logger)

	<-ctx.Done()

	// For timeline-based formats, build the capture and export.
	if tb != nil {
		// Diagnostic: log GVL suspended stack counts
		for tid, count := range tb.SuspendedStackCounts() {
			logger.Info("gvl_stack events received", "tid", tid, "count", count)
		}
		// Diagnostic: log regular sample counts per thread
		for tid, count := range tb.SampleCounts() {
			if count > 0 {
				logger.Info("regular samples", "tid", tid, "count", count)
			}
		}

		capture := tb.Build()
		tb.CloseFrameResolver() // release cached /proc/pid/mem fds
		switch flagCaptureFormat {
		case "gecko":
			if err := gecko.Export(capture, flagCaptureOutput); err != nil {
				return fmt.Errorf("export gecko profile: %w", err)
			}
			logger.Info("gecko profile exported", "output", flagCaptureOutput)
		case "csv":
			if err := csvexport.Export(capture, flagCaptureOutput); err != nil {
				return fmt.Errorf("export csv: %w", err)
			}
			logger.Info("csv export complete", "output", flagCaptureOutput)
		}
	}

	logger.Info("capture complete", "output", flagCaptureOutput, "duration", flagCaptureDuration)
	return nil
}

// timelineExporter routes events to a timeline.Builder.
type timelineExporter struct {
	builder *timeline.Builder
}

func (e *timelineExporter) Export(_ context.Context, event any) error {
	e.builder.Ingest(event)
	return nil
}

func (e *timelineExporter) Flush(_ context.Context) error { return nil }
func (e *timelineExporter) Close() error                  { return nil }

// attachSiblingPIDs finds all processes that share the same parent as the
// target PID and have rbscope.so loaded, then adds them to the I/O tracer's
// target_pids map. This is needed because Pitchfork forks workers that
// inherit the uprobe but the I/O tracepoints need explicit PID filtering.
func attachSiblingPIDs(c *collector.Collector, targetPID uint32, logger *slog.Logger) {
	// Read target's PPID
	ppid := readPPID(targetPID)
	if ppid == 0 {
		return
	}

	// Scan /proc for siblings with the same parent
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || uint32(pid) == targetPID {
			continue
		}
		if readPPID(uint32(pid)) != ppid {
			continue
		}
		// Check if this sibling has rbscope.so mapped
		if hasRbscopeLoaded(uint32(pid)) {
			if err := c.AttachPID(uint32(pid)); err != nil {
				logger.Debug("attach sibling", "pid", pid, "err", err)
			} else {
				logger.Info("attached sibling worker", "pid", pid)
			}
		}
	}
}

func readPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseUint(fields[1], 10, 32)
				return uint32(v)
			}
		}
	}
	return 0
}

func hasRbscopeLoaded(pid uint32) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "rbscope") {
			return true
		}
	}
	return false
}

func buildExporters(logger *slog.Logger) ([]collector.Exporter, error) {
	names := strings.Split(flagExport, ",")
	var exporters []collector.Exporter

	for _, name := range names {
		switch strings.TrimSpace(name) {
		case "pyroscope":
			logger.Info("enabling pyroscope exporter (unified stacks)", "url", flagPyroscopeURL)
			hostname, _ := os.Hostname()
			tb := timeline.NewBuilder("rbscope", hostname, flagPID, uint32(flagFrequency)) //nolint:gosec // frequency is always small positive
			if flagPID != 0 {
				if resolver, err := symbols.NewResolver(flagPID); err == nil {
					tb.SetResolver(resolver)
					logger.Info("native stack resolution enabled", "pid", flagPID)
				}
			}
			exporters = append(exporters, export.NewBuilderPyroscopeExporter(export.BuilderPyroscopeConfig{
				Builder:    tb,
				ServerURL:  flagPyroscopeURL,
				AppName:    "rbscope.cpu",
				FlushEvery: 10 * time.Second,
				Logger:     logger,
			}))
		case "datadog":
			logger.Info("enabling datadog exporter", "url", flagDatadogURL)
			apiKey := os.Getenv("DD_API_KEY")
			if apiKey == "" {
				return nil, fmt.Errorf("DD_API_KEY environment variable required for datadog exporter")
			}
			exporters = append(exporters, export.NewDatadogExporter(export.DatadogConfig{
				IntakeURL:  flagDatadogURL,
				APIKey:     apiKey,
				Service:    os.Getenv("DD_SERVICE"),
				Env:        os.Getenv("DD_ENV"),
				Version:    os.Getenv("DD_VERSION"),
				FlushEvery: 60 * time.Second,
				Logger:     logger,
			}))
		case "otlp":
			logger.Info("enabling otlp exporter", "endpoint", flagOTLPEndpoint)
			exporters = append(exporters, export.NewOTLPExporter(export.OTLPConfig{
				Endpoint:    flagOTLPEndpoint,
				ServiceName: "rbscope",
				FlushEvery:  10 * time.Second,
				Logger:      logger,
			}))
		case "file":
			path := flagOutputDir + "/capture.pb"
			logger.Info("enabling file exporter", "path", path)
			fe, err := export.NewFileExporter(path)
			if err != nil {
				return nil, fmt.Errorf("create file exporter: %w", err)
			}
			exporters = append(exporters, fe)
		default:
			return nil, fmt.Errorf("unknown exporter: %q", name)
		}
	}

	return exporters, nil
}

// demo flags
var (
	flagDemoPyroscopeURL string
	flagDemoAppName      string
	flagDemoFreq         int
	flagDemoHealthPort   int
)

func demoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run with simulated Ruby profiling data (no BPF needed)",
		Long: `Generates realistic Ruby/Rails stack samples and pushes them to Pyroscope.
Use this to test the full pipeline on any OS — no Linux, no CAP_BPF, no real Ruby process required.`,
		RunE: runDemo,
	}

	f := cmd.Flags()
	f.StringVar(&flagDemoPyroscopeURL, "pyroscope-url", "http://localhost:4040", "Pyroscope server URL")
	f.StringVar(&flagDemoAppName, "app-name", "rbscope-demo{service=rails,env=development}", "Application name in Pyroscope")
	f.IntVar(&flagDemoFreq, "frequency", 99, "Simulated sampling frequency in Hz")
	f.IntVar(&flagDemoHealthPort, "health-port", 8080, "Health/metrics HTTP port")

	return cmd
}

func runDemo(_ *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	logger.Info("starting demo mode",
		"frequency_hz", flagDemoFreq,
		"pyroscope_url", flagDemoPyroscopeURL,
		"app_name", flagDemoAppName,
	)

	simBPF := collector.NewSimBPF(flagDemoFreq)

	pyroExporter := export.NewPyroscopePushExporter(export.PyroscopePushConfig{
		ServerURL:  flagDemoPyroscopeURL,
		AppName:    flagDemoAppName,
		SymbolMap:  collector.SimStackNames,
		FlushEvery: 10 * time.Second,
		Logger:     logger,
	})

	cfg := collector.Config{
		FrequencyHz: flagDemoFreq,
		Exporters:   []collector.Exporter{pyroExporter},
		Logger:      logger,
	}

	c := collector.New(cfg, simBPF)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go serveHealth(ctx, logger)

	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("start collector: %w", err)
	}
	defer func() { _ = c.Stop() }()

	// Attach a fake PID to start generating events.
	if err := c.AttachPID(1); err != nil {
		return err
	}

	logger.Info("demo running — simulated Ruby profiles streaming to Pyroscope (Ctrl+C to stop)")
	<-ctx.Done()
	logger.Info("shutting down demo")
	return nil
}

func serveHealth(ctx context.Context, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", flagHealthPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("health server listening", "port", flagHealthPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("health server failed", "err", err)
	}
}
