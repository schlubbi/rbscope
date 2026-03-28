# Contributing to rbscope

## Development Setup

rbscope has three components: a **Ruby gem** (Rust native extension), a **Go collector** (with eBPF), and **BPF programs** (C, compiled via bpf2go). You can work on the gem and collector Go code from macOS. BPF compilation and integration testing requires Linux.

### macOS (Apple Silicon)

**Prerequisites:** [OrbStack](https://orbstack.dev) (already manages Docker — also provides lightweight Linux VMs).

```bash
# One-time: create and provision a Linux VM with all build deps
make vm-setup

# Run BPF loading tests
make vm-test-bpf

# Run full E2E (gem + collector + BPF)
make vm-test-e2e

# Interactive VM shell for debugging
make vm-shell
```

The VM shares your macOS filesystem — edit code in your normal editor, run tests via `make vm-*`. No file sync, no lag.

**Unit tests run directly on macOS** (no VM needed):

```bash
make test-gem        # Ruby + Rust tests
make test-collector  # Go tests (BPF operations are stubbed on non-Linux)
make test-all        # Both
```

### Linux

Everything runs natively:

```bash
# Install deps (Ubuntu/Debian)
sudo apt-get install -y build-essential clang llvm libbpf-dev \
    linux-headers-$(uname -r) bpftool golang-go ruby ruby-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Generate BPF objects from C sources
cd collector && go generate ./pkg/bpf/

# Run everything
make test-all
sudo go test -v ./test/bpf/...                    # BPF load tests
sudo go test -v -tags=integration ./...            # integration tests
```

### Codespaces / devcontainer

The project includes a `.devcontainer/devcontainer.json` that installs Go, Rust, and Ruby. Open in GitHub Codespaces or VS Code Dev Containers.

## Project Layout

```
rbscope/
├── gem/                    # Ruby gem with Rust native extension
│   ├── ext/rbscope/        #   Rust source (sampler, probes, USDT)
│   ├── lib/                #   Ruby source
│   └── test/               #   Ruby tests (minitest)
├── collector/              # Go collector + eBPF programs
│   ├── cmd/                #   CLI entry point
│   ├── pkg/bpf/            #   BPF C sources + bpf2go generation
│   ├── pkg/collector/      #   Core collector logic
│   ├── pkg/export/         #   Exporters (Pyroscope, OTLP, Datadog, ...)
│   └── test/bpf/           #   BPF loading regression tests
├── proto/                  # Protobuf definitions
├── test-rails-app/         # Demo Rails app for smoke tests
├── scripts/                # Dev scripts (VM setup, smoke test)
└── .github/workflows/      # CI pipelines
```

## Make Targets

```
make help              Show all targets
make test-all          Run gem + collector unit tests (macOS or Linux)
make test-gem          Ruby gem tests only
make test-collector    Go collector tests only (BPF stubbed on non-Linux)

make vm-setup          Create OrbStack Linux VM with build deps
make vm-test           Unit + BPF tests in VM
make vm-test-bpf       BPF loading tests only (fast, no Ruby)
make vm-test-e2e       Full E2E: gem + collector + BPF
make vm-generate       Generate BPF objects in VM (for arm64)
make vm-shell          Interactive VM shell
make vm-destroy        Delete the VM

make demo-up           Start full Docker Compose stack
make demo-down         Stop the stack
make smoke-test        Run smoke tests against running stack
```

## CI Pipelines

| Workflow | What it tests | Trigger |
|---|---|---|
| **gem-ci.yml** | Ruby 3.3/3.4/4.0/head, Rust tests, clippy, valgrind, ASAN/TSAN, miri | Push to `gem/**` |
| **collector-ci.yml** | Go 1.23/1.24, race detector, golangci-lint | Push to `collector/**` |
| **ebpf-e2e.yml** | Full E2E (gem + collector + BPF) on ubuntu-22.04/24.04 | Push to main, PRs |
| **ebpf-e2e.yml** (bpf-compat) | BPF load tests via vimto on kernels 6.1, 6.8, stable | Push to main, PRs |
| **fuzz-nightly.yml** | Rust fuzzing (stack serialization) | Nightly at 4am UTC |

## Adding a New BPF Program

1. Write the C source in `collector/pkg/bpf/your_tracer.c`
2. Add `go:generate` lines in `collector/pkg/bpf/generate.go` for both amd64 and arm64
3. Run `make vm-generate` (or `go generate ./pkg/bpf/` on Linux) to produce Go bindings
4. Add a load test in `collector/test/bpf/load_test.go`
5. Verify: `make vm-test-bpf`

## Commit Guidelines

Use conventional commits. The subject line should be imperative mood, ≤72 chars:

```
feat(collector): add FD resolution to periodic sampler
fix(gem): prevent double-free in allocation tracker
test(bpf): add load tests for sched_tracer on arm64
ci: add vimto kernel matrix for BPF compat testing
```
