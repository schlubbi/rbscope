//go:build linux

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang rbscope ruby_reader.c -- -I. -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang iotracer io_tracer.c -- -I. -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang schedtracer sched_tracer.c -- -I. -D__TARGET_ARCH_x86
