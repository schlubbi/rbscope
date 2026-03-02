package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/google/pprof/profile"
	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// DatadogConfig configures the Datadog profiling exporter.
type DatadogConfig struct {
	IntakeURL       string
	APIKey          string
	Service         string
	Env             string
	Version         string
	Tags            map[string]string
	SymbolMap       map[uint32][]string // stackID → frame names (for demo mode)
	FlushEvery      time.Duration
	Logger          *slog.Logger
}

// DatadogExporter implements collector.Exporter by accumulating stack samples
// into pprof profiles and pushing them to the Datadog profiling intake.
type DatadogExporter struct {
	cfg        DatadogConfig
	log        *slog.Logger
	httpClient *http.Client

	mu      sync.Mutex
	builder *profile.Profile
	funcMap map[string]*profile.Function
	locMap  map[uint64]*profile.Location
	funcID  uint64
	locID   uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDatadogExporter creates an exporter that pushes profiles to Datadog.
func NewDatadogExporter(cfg DatadogConfig) *DatadogExporter {
	if cfg.IntakeURL == "" {
		cfg.IntakeURL = "https://intake.profile.datadoghq.com"
	}
	if cfg.FlushEvery == 0 {
		cfg.FlushEvery = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &DatadogExporter{
		cfg: cfg,
		log: cfg.Logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		funcMap: make(map[string]*profile.Function),
		locMap:  make(map[uint64]*profile.Location),
		ctx:     ctx,
		cancel:  cancel,
	}
	e.resetProfile()

	e.wg.Add(1)
	go e.flushLoop()

	return e
}

// Export handles a decoded event from the collector.
func (e *DatadogExporter) Export(_ context.Context, event any) error {
	sample, ok := event.(*collector.RubySampleEvent)
	if !ok {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	locs := e.resolveStack(sample)
	if len(locs) == 0 {
		return nil
	}

	e.builder.Sample = append(e.builder.Sample, &profile.Sample{
		Location: locs,
		Value:    []int64{1, 10000000}, // 1 sample, 10ms cpu
	})
	return nil
}

// Flush pushes the accumulated profile to Datadog.
func (e *DatadogExporter) Flush(ctx context.Context) error {
	return e.pushProfile(ctx)
}

// Close stops the background flush loop and pushes remaining data.
func (e *DatadogExporter) Close() error {
	e.cancel()
	e.wg.Wait()
	return e.pushProfile(context.Background())
}

func (e *DatadogExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.cfg.FlushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.pushProfile(e.ctx); err != nil {
				e.log.Warn("datadog flush failed", "err", err)
			}
		}
	}
}

func (e *DatadogExporter) pushProfile(ctx context.Context) error {
	e.mu.Lock()
	prof := e.builder
	sampleCount := len(prof.Sample)
	e.resetProfile()
	e.mu.Unlock()

	if sampleCount == 0 {
		return nil
	}

	prof.DurationNanos = e.cfg.FlushEvery.Nanoseconds()
	prof.TimeNanos = time.Now().UnixNano()

	body, contentType, err := e.buildMultipartForm(prof)
	if err != nil {
		return fmt.Errorf("datadog: build form: %w", err)
	}

	url := strings.TrimRight(e.cfg.IntakeURL, "/") + "/api/v2/profile"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("datadog: create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("DD-API-KEY", e.cfg.APIKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: push: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("datadog: unexpected status %d", resp.StatusCode)
	}

	e.log.Info("pushed profile to datadog", "samples", sampleCount)
	return nil
}

// datadogEvent is the JSON metadata sent in the "event" form part.
type datadogEvent struct {
	Attachments    []string `json:"attachments"`
	TagsProfiler   string   `json:"tags_profiler"`
	Family         string   `json:"family"`
	Version        string   `json:"version"`
}

func (e *DatadogExporter) buildMultipartForm(prof *profile.Profile) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Write the event JSON part.
	tags := e.buildTagsProfiler()
	event := datadogEvent{
		Attachments:  []string{"profile.pprof"},
		TagsProfiler: tags,
		Family:       "ruby",
		Version:      "4",
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, "", fmt.Errorf("marshal event: %w", err)
	}

	eventHeader := make(textproto.MIMEHeader)
	eventHeader.Set("Content-Disposition", `form-data; name="event"; filename="event.json"`)
	eventHeader.Set("Content-Type", "application/json")
	eventPart, err := w.CreatePart(eventHeader)
	if err != nil {
		return nil, "", fmt.Errorf("create event part: %w", err)
	}
	if _, err := eventPart.Write(eventJSON); err != nil {
		return nil, "", fmt.Errorf("write event part: %w", err)
	}

	// Write the pprof profile part (gzipped by prof.Write).
	profHeader := make(textproto.MIMEHeader)
	profHeader.Set("Content-Disposition", `form-data; name="profile.pprof"; filename="profile.pprof"`)
	profHeader.Set("Content-Type", "application/octet-stream")
	profPart, err := w.CreatePart(profHeader)
	if err != nil {
		return nil, "", fmt.Errorf("create profile part: %w", err)
	}
	if err := prof.Write(profPart); err != nil {
		return nil, "", fmt.Errorf("write profile: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart: %w", err)
	}

	return &buf, w.FormDataContentType(), nil
}

func (e *DatadogExporter) buildTagsProfiler() string {
	parts := []string{
		"service:" + e.cfg.Service,
		"env:" + e.cfg.Env,
		"version:" + e.cfg.Version,
		"runtime:ruby",
		"profiler_version:rbscope",
		"language:ruby",
	}
	for k, v := range e.cfg.Tags {
		parts = append(parts, k+":"+v)
	}
	return strings.Join(parts, ",")
}

func (e *DatadogExporter) resetProfile() {
	e.builder = &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: "nanoseconds"},
		},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:     int64(10000000), // 10ms = 100Hz equivalent
	}
	e.funcMap = make(map[string]*profile.Function)
	e.locMap = make(map[uint64]*profile.Location)
	e.funcID = 0
	e.locID = 0
}

func (e *DatadogExporter) resolveStack(sample *collector.RubySampleEvent) []*profile.Location {
	names, ok := e.cfg.SymbolMap[sample.StackID]
	if !ok {
		names = []string{fmt.Sprintf("ruby_frame_0x%x", sample.StackID)}
	}

	locs := make([]*profile.Location, 0, len(names))
	for _, name := range names {
		addr := hashName(name)
		loc, exists := e.locMap[addr]
		if !exists {
			fn := e.getOrCreateFunc(name)
			e.locID++
			loc = &profile.Location{
				ID:      e.locID,
				Address: addr,
				Line: []profile.Line{
					{Function: fn, Line: 1},
				},
			}
			e.locMap[addr] = loc
			e.builder.Location = append(e.builder.Location, loc)
		}
		locs = append(locs, loc)
	}
	return locs
}

func (e *DatadogExporter) getOrCreateFunc(name string) *profile.Function {
	if fn, ok := e.funcMap[name]; ok {
		return fn
	}
	e.funcID++
	fn := &profile.Function{
		ID:   e.funcID,
		Name: name,
	}
	e.funcMap[name] = fn
	e.builder.Function = append(e.builder.Function, fn)
	return fn
}
