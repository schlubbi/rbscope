//go:build linux

package bpf

// Requires clang >= 14 and -mcpu=v3 for BPF atomic operations (kernel >= 5.12).
// Override CC with: CLANG=clang-14 go generate ./pkg/bpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang rbscope ruby_reader.c -- -I. -D__TARGET_ARCH_x86 -mcpu=v3
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang iotracer io_tracer.c -- -I. -D__TARGET_ARCH_x86 -mcpu=v3
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang schedtracer sched_tracer.c -- -I. -D__TARGET_ARCH_x86 -mcpu=v3
