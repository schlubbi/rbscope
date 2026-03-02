package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/schlubbi/rbscope/collector/internal"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
	"github.com/schlubbi/rbscope/collector/pkg/discovery"
	"github.com/schlubbi/rbscope/collector/pkg/export"
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
)

// capture flags
var (
	flagCapturePID      uint32
	flagCaptureDuration time.Duration
	flagCaptureOutput   string
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

	c := collector.New(cfg, nil) // nil BPF → stub on non-Linux

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

	fe, err := export.NewFileExporter(flagCaptureOutput)
	if err != nil {
		return err
	}
	defer func() { _ = fe.Close() }()

	cfg := collector.Config{
		FrequencyHz: 99, // higher frequency for captures
		Logger:      logger,
	}

	c := collector.New(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), flagCaptureDuration)
	defer cancel()

	if err := c.Start(ctx); err != nil {
		return err
	}
	defer func() { _ = c.Stop() }()

	if err := c.AttachPID(flagCapturePID); err != nil {
		return err
	}

	<-ctx.Done()
	logger.Info("capture complete", "output", flagCaptureOutput, "duration", flagCaptureDuration)
	return nil
}

func buildExporters(logger *slog.Logger) ([]collector.Exporter, error) {
	names := strings.Split(flagExport, ",")
	var exporters []collector.Exporter

	for _, name := range names {
		switch strings.TrimSpace(name) {
		case "pyroscope":
			logger.Info("enabling pyroscope exporter", "url", flagPyroscopeURL)
			// Pyroscope exporter is configured but not wired as an
			// Exporter interface implementation yet—push is done at
			// the flush boundary via PprofBuilder.
		case "datadog":
			logger.Info("enabling datadog exporter", "url", flagDatadogURL)
		case "otlp":
			logger.Info("enabling otlp exporter", "endpoint", flagOTLPEndpoint)
		case "file":
			logger.Info("enabling file exporter", "dir", flagOutputDir)
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
		Addr:    fmt.Sprintf(":%d", flagHealthPort),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("health server listening", "port", flagHealthPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("health server failed", "err", err)
	}
}
