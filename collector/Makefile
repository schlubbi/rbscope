.PHONY: all build test test-race lint clean generate proto

# Go parameters
GOOS ?= linux
GOARCH ?= amd64
BINARY = rbscope-collector
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X github.com/schlubbi/rbscope/collector/internal.Version=$(VERSION) -s -w"

all: generate build

# Build the collector binary (statically linked for containers)
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/rbscope-collector

# Generate BPF code from C sources using bpf2go
# Requires: linux, clang, libbpf headers
generate:
	@echo "Generating BPF objects (requires Linux + clang)..."
	cd pkg/bpf && go generate ./...

# Generate protobuf Go code
proto:
	protoc --go_out=. --go_opt=paths=source_relative proto/rbscope.proto

# Run all tests
test:
	go test ./... -v -count=1

# Run tests with race detector
test-race:
	go test -race ./... -count=1

# Run integration tests (require CAP_BPF on Linux)
test-integration:
	go test -tags=integration -v -count=1 ./...

# Lint
lint:
	golangci-lint run --timeout=5m

# Clean build artifacts
clean:
	rm -rf bin/

# Build Docker image
docker:
	docker build -t rbscope-collector:$(VERSION) -f Dockerfile ..

# Deploy to kind cluster
kind-deploy:
	kubectl apply -f deploy/k8s/namespace.yaml
	kubectl apply -f deploy/k8s/rbac.yaml
	kubectl apply -f deploy/k8s/configmap.yaml
	kubectl apply -f deploy/k8s/daemonset.yaml
