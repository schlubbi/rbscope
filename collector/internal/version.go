// Package internal holds build-time version metadata for rbscope-collector.
package internal

// Set via ldflags at build time.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)
