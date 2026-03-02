# Multi-stage build for rbscope-collector
# Produces a minimal static binary with no runtime dependencies

FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Copy module files first for layer caching
COPY collector/go.mod collector/go.sum ./
RUN go mod download

# Copy source
COPY collector/ .
COPY proto/ ../proto/

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X github.com/schlubbi/rbscope/collector/internal.Version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /rbscope-collector \
    ./cmd/rbscope-collector

# Runtime image — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /rbscope-collector /rbscope-collector

# Health check port
EXPOSE 8080

ENTRYPOINT ["/rbscope-collector"]
CMD ["run"]
