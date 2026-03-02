package export

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/pprof/profile"
)

// PyroscopeExporter pushes pprof profiles to a Pyroscope-compatible server.
type PyroscopeExporter struct {
	serverURL  string
	appName    string
	labels     map[string]string
	httpClient *http.Client
}

// PyroscopeConfig configures the Pyroscope exporter.
type PyroscopeConfig struct {
	ServerURL string
	AppName   string            // e.g. "rbscope.cpu"
	Labels    map[string]string // static labels: service, pod, etc.
}

// NewPyroscopeExporter creates a new exporter targeting the given server.
func NewPyroscopeExporter(cfg PyroscopeConfig) *PyroscopeExporter {
	return &PyroscopeExporter{
		serverURL: cfg.ServerURL,
		appName:   cfg.AppName,
		labels:    cfg.Labels,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Push serialises the profile and sends it to the Pyroscope /ingest endpoint.
func (e *PyroscopeExporter) Push(ctx context.Context, prof *profile.Profile) error {
	var buf bytes.Buffer
	if err := prof.Write(&buf); err != nil {
		return fmt.Errorf("pyroscope: serialize profile: %w", err)
	}

	u, err := url.Parse(e.serverURL)
	if err != nil {
		return fmt.Errorf("pyroscope: parse url: %w", err)
	}
	u.Path = "/ingest"

	q := u.Query()
	q.Set("name", e.labeledAppName())
	q.Set("format", "pprof")
	q.Set("sampleRate", "19")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &buf)
	if err != nil {
		return fmt.Errorf("pyroscope: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pyroscope: push: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("pyroscope: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// labeledAppName builds "appName{key=val,...}" for Pyroscope.
func (e *PyroscopeExporter) labeledAppName() string {
	if len(e.labels) == 0 {
		return e.appName
	}
	s := e.appName + "{"
	first := true
	for k, v := range e.labels {
		if !first {
			s += ","
		}
		s += k + "=" + v
		first = false
	}
	s += "}"
	return s
}
