# rbscope Testing Guide

## Quick Start

```bash
# Tier 1: Ruby gem tests
cd gem && bundle exec rake clobber compile test

# Tier 1: Rust unit tests
cd gem/ext/rbscope && cargo test

# Tier 2: Go collector tests
cd collector && go test ./...

# Tier 2: Go race detection
cd collector && go test -race ./...

# Tier 2: Go lint
cd collector && golangci-lint run
```

## Phase 1 Verification Gate (Tier 1)

**Standalone — no collector needed:**

1. Build and test the gem:
   ```bash
   cd gem
   bundle install
   bundle exec rake clobber compile test
   ```

2. Run Rust tests:
   ```bash
   cd gem/ext/rbscope
   cargo test
   cargo clippy -- -D warnings
   ```

3. Start the test Rack app:
   ```bash
   cd test-rails-app
   bundle install
   bundle exec puma -p 3000
   ```

4. Verify endpoints:
   ```bash
   curl http://localhost:3000/fast      # ~1ms response
   curl http://localhost:3000/slow      # ~500ms (sleep)
   curl http://localhost:3000/allocate  # allocates 10k objects
   ```

5. Check USDT probes (Linux only):
   ```bash
   bpftrace -l 'usdt:*:rbscope:*'
   ```

### Safety Tooling

**Valgrind:**
```bash
cd gem
RBSCOPE_VALGRIND=1 valgrind --tool=memcheck --leak-check=full \
  --suppressions=valgrind.suppressions \
  ruby -Ilib -Iext test/test_sampling.rb
```

**AddressSanitizer (ASAN):**
```bash
cd gem/ext/rbscope
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu
```

**ThreadSanitizer (TSAN):**
```bash
cd gem/ext/rbscope
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --target x86_64-unknown-linux-gnu
```

**Miri (undefined behavior in unsafe blocks):**
```bash
cd gem/ext/rbscope
cargo +nightly miri test
```

## Phase 2 Verification Gate (Tier 2)

**Collector + gem on a single Linux box:**

1. Start the test Rack app (same as Phase 1)

2. Start the collector:
   ```bash
   cd collector
   make build
   ./bin/rbscope-collector run --pid $(pgrep -f puma) --frequency 99 --export file --output-dir /tmp/rbscope
   ```

3. Generate load:
   ```bash
   wrk -t2 -c10 -d30s http://localhost:3000/fast
   wrk -t2 -c10 -d30s http://localhost:3000/slow
   ```

4. Verify output files in `/tmp/rbscope/`

### Kind Cluster Test

```bash
# Create cluster
kind create cluster --config kind/cluster.yaml

# Build and load images
docker build -t test-rails-app:dev -f test-rails-app/Dockerfile test-rails-app/
docker build -t rbscope-collector:dev -f collector/Dockerfile .
kind load docker-image test-rails-app:dev rbscope-collector:dev

# Deploy
kubectl apply -f kind/manifests/test-app.yaml
kubectl apply -f kind/manifests/rbscope-collector.yaml

# Verify
kubectl get pods -n rbscope
kubectl logs -n rbscope -l app=rbscope-collector
```

## Phase 3 Verification Gate (Full Stack)

**Local full-stack environment:**

```bash
# Start backends
docker-compose up -d

# Verify services
curl http://localhost:4040  # Pyroscope UI
curl http://localhost:16686 # Jaeger UI

# Start kind cluster with test app + collector (same as Phase 2)
# Generate load
wrk -t4 -c20 -d60s http://localhost:3000/slow

# Check Pyroscope for flame graphs
# Check Jaeger for traces with profile data
```

## CI Matrix

The project has two CI workflows:

### gem-ci.yml (Tier 1)
- Ruby 3.3/3.4/head on Ubuntu
- Valgrind job
- ASAN + TSAN sanitizer jobs
- Miri job for Rust unsafe blocks

### collector-ci.yml (Tier 2)
- Go 1.23/1.24 on Ubuntu
- Race detector
- golangci-lint
- Integration tests (require CAP_BPF)
