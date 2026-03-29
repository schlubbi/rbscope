//go:build !linux

package bpf

import (
	"fmt"
	"runtime"

	"github.com/schlubbi/rbscope/collector/pkg/collector"
)

// RealBPF is a placeholder on non-Linux platforms.
type RealBPF struct{}

var _ collector.BPFProgram = (*RealBPF)(nil)

// NewRealBPF returns an error on non-Linux platforms.
func NewRealBPF(_ string) (*RealBPF, error) {
	return nil, fmt.Errorf("BPF not supported on this platform (%s/%s)", runtime.GOOS, runtime.GOARCH)
}

func (r *RealBPF) Load() error              { return fmt.Errorf("BPF not supported on this platform") }
func (r *RealBPF) AttachPID(_ uint32) error { return fmt.Errorf("BPF not supported on this platform") }
func (r *RealBPF) DetachPID(_ uint32) error { return fmt.Errorf("BPF not supported on this platform") }
func (r *RealBPF) ReadRingBuffer(_ []byte) (int, error) {
	return 0, fmt.Errorf("BPF not supported on this platform")
}
func (r *RealBPF) KtimeOffsetNs() int64 { return 0 }
func (r *RealBPF) Close() error         { return nil }
