// Package bpf provides the real eBPF-backed implementation of the
// collector.BPFProgram interface. On Linux it loads compiled BPF objects,
// attaches uprobes to target processes, and reads events from a ring buffer.
// On other platforms NewRealBPF returns an error.
package bpf
