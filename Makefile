.PHONY: help test-gem test-collector test-all demo-up demo-down smoke-test clean
.PHONY: vm-setup vm-test vm-test-bpf vm-test-e2e vm-shell vm-destroy

VM_NAME ?= rbscope-dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Unit tests (no kernel needed, runs on macOS or Linux) ---

test-gem: ## Run Ruby gem tests (needs Ruby + Rust)
	cd gem && bundle install --quiet && bundle exec rake clobber compile test

test-collector: ## Run Go collector tests (no BPF)
	cd collector && go test -race -short ./...

test-all: test-gem test-collector ## Run all unit tests

# --- OrbStack Linux VM (macOS → Linux for eBPF testing) ---

vm-setup: ## Create and provision OrbStack Linux VM
	@scripts/setup-dev-vm.sh $(VM_NAME)

vm-shell: ## Drop into interactive VM shell
	orbctl run -m $(VM_NAME) -s

vm-test: ## Run unit + BPF tests in VM
	orbctl run -m $(VM_NAME) -u root -w $(CURDIR) bash -c '\
		. $$HOME/.cargo/env 2>/dev/null; \
		cd collector && go test -v -count=1 -short ./... && \
		echo "" && echo "=== BPF load tests ===" && \
		go test -v -count=1 ./test/bpf/...'

vm-test-bpf: ## Run BPF loading tests in VM (fast, no Ruby)
	orbctl run -m $(VM_NAME) -u root -w $(CURDIR) bash -c '\
		cd collector && go test -v -count=1 ./test/bpf/...'

vm-test-e2e: ## Run full E2E in VM (Ruby + collector + BPF)
	orbctl run -m $(VM_NAME) -u root -w $(CURDIR) bash -c '\
		. $$HOME/.cargo/env 2>/dev/null; \
		cd gem && bundle install --quiet && bundle exec rake compile && \
		cd ../collector && \
		go generate ./pkg/bpf/ && \
		go build -o bin/rbscope-collector ./cmd/rbscope-collector/ && \
		go test -v -count=1 -tags=integration ./...'

vm-generate: ## Generate BPF objects in VM (for arm64)
	orbctl run -m $(VM_NAME) -u root -w $(CURDIR) bash -c '\
		cd collector && go generate ./pkg/bpf/'

vm-destroy: ## Delete the VM
	orbctl delete $(VM_NAME) 2>/dev/null || true

# --- Docker-based demo stack ---

demo-up: ## Start full stack: test-app + collector (demo) + Jaeger + Pyroscope
	docker compose up -d --build
	@echo ""
	@echo "🔭 rbscope demo stack starting..."
	@echo "   Test app:   http://localhost:3000/slow"
	@echo "   Jaeger UI:  http://localhost:16686"
	@echo "   Pyroscope:  http://localhost:4040"
	@echo "   Collector:  http://localhost:8080/healthz"
	@echo ""
	@echo "Run 'make smoke-test' once services are healthy."

demo-down: ## Stop the demo stack
	docker compose down -v

smoke-test: ## Run end-to-end smoke tests against running stack
	@scripts/smoke-test.sh

clean: ## Remove build artifacts
	cd gem && bundle exec rake clobber 2>/dev/null || true
	cd collector && go clean ./... 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
