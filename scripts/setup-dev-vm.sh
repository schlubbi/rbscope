#!/usr/bin/env bash
#
# Provision an OrbStack Linux VM for rbscope development.
# Installs: Go, Rust, Ruby, clang/LLVM, libbpf, kernel headers, bpftool.
#
# Usage:
#   ./scripts/setup-dev-vm.sh [VM_NAME]
#
# The VM shares your macOS filesystem — edits on macOS are immediately
# visible inside the VM. No file sync needed.
#
set -euo pipefail

VM_NAME="${1:-rbscope-dev}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}▸${NC} $*"; }
warn()  { echo -e "${YELLOW}▸${NC} $*"; }
error() { echo -e "${RED}▸${NC} $*" >&2; }

# --- Preflight ---

if ! command -v orbctl &>/dev/null; then
    error "OrbStack not found. Install from https://orbstack.dev or: brew install orbstack"
    exit 1
fi

if ! orbctl status &>/dev/null; then
    error "OrbStack is not running. Start it first."
    exit 1
fi

# --- Create VM if needed ---

if orbctl list 2>/dev/null | grep -q "$VM_NAME"; then
    info "VM '$VM_NAME' already exists"
else
    info "Creating Ubuntu 24.04 VM: $VM_NAME"
    orbctl create ubuntu:24.04 "$VM_NAME"
fi

# --- Provision ---

info "Provisioning VM (this takes ~2 min on first run)..."

orbctl run -m "$VM_NAME" -u root bash -euxo pipefail <<'PROVISION'

export DEBIAN_FRONTEND=noninteractive

# --- System packages ---
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    clang llvm \
    libelf-dev libbpf-dev \
    pkg-config cmake \
    protobuf-compiler \
    curl git jq \
    ruby ruby-dev

# Kernel headers and bpftool — best-effort, OrbStack uses a custom kernel
# so the matching linux-headers package won't exist. CO-RE (BTF) works without
# headers; bpf2go compiles against vmlinux.h which is checked into the repo.
apt-get install -y -qq linux-headers-$(uname -r) 2>/dev/null || \
    echo "⚠ No kernel headers for $(uname -r) — OK, using vmlinux.h from repo"
apt-get install -y -qq linux-tools-common linux-tools-$(uname -r) bpftool 2>/dev/null || \
    apt-get install -y -qq bpftools 2>/dev/null || \
    echo "⚠ bpftool not available — install manually if needed"

# --- Go (latest stable from official tarball) ---
if ! command -v go &>/dev/null || [[ "$(go version)" != *"go1.24"* ]]; then
    GOARCH=$(dpkg --print-architecture)
    GO_VERSION="1.24.2"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -C /usr/local -xz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

# --- Rust ---
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi

# --- Verify BPF support ---
echo ""
echo "=== Environment ==="
uname -r
go version
rustc --version 2>/dev/null || echo "rustc: installed via rustup (source .cargo/env)"
ruby --version
clang --version | head -1
echo ""

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✅ BTF available at /sys/kernel/btf/vmlinux"
else
    echo "⚠️  No BTF — CO-RE may not work on this kernel"
fi

# Quick BPF smoke test
if command -v bpftool &>/dev/null; then
    bpftool prog list 2>/dev/null | head -3 || true
    echo "✅ bpftool works"
fi

echo ""
echo "✅ VM '$HOSTNAME' provisioned successfully"

PROVISION

info "Done! VM '$VM_NAME' is ready."
echo ""
echo "  Usage:"
echo "    make vm-test          # Run all tests in VM"
echo "    make vm-test-bpf      # BPF loading tests only"
echo "    make vm-shell         # Interactive shell"
echo ""
