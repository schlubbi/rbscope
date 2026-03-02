.PHONY: help test-gem test-collector test-all demo-up demo-down smoke-test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Unit tests (no Docker needed) ---

test-gem: ## Run Ruby gem tests (needs Ruby + Rust)
	cd gem && bundle install --quiet && bundle exec rake clobber compile test

test-collector: ## Run Go collector tests
	cd collector && go test -race ./...

test-all: test-gem test-collector ## Run all unit tests

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
