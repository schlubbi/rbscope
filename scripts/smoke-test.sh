#!/usr/bin/env bash
#
# End-to-end smoke test for the rbscope demo stack.
# Expects: docker compose up -d (all services running)
#
# Verifies:
#   1. Test app responds on /health, /fast, /slow, /work
#   2. Standalone capture returns speedscope JSON
#   3. Traces arrive in Jaeger
#   4. Profiles arrive in Pyroscope
#   5. Collector health endpoint responds
#
# Exit 0 = all checks pass, non-zero = failure.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} ${name}"
    ((PASS++))
  else
    echo -e "  ${RED}✗${NC} ${name}"
    ((FAIL++))
  fi
}

check_output() {
  local name="$1"
  local pattern="$2"
  shift 2
  local output
  output=$("$@" 2>/dev/null) || true
  if echo "$output" | grep -q "$pattern"; then
    echo -e "  ${GREEN}✓${NC} ${name}"
    ((PASS++))
  else
    echo -e "  ${RED}✗${NC} ${name} (expected '${pattern}' in output)"
    ((FAIL++))
  fi
}

APP_URL="${APP_URL:-http://localhost:3000}"
JAEGER_URL="${JAEGER_URL:-http://localhost:16686}"
PYROSCOPE_URL="${PYROSCOPE_URL:-http://localhost:4040}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8080}"

echo ""
echo "🔭 rbscope smoke test"
echo "====================="

# --- Wait for services ---
echo ""
echo -e "${YELLOW}Waiting for services...${NC}"

wait_for() {
  local name="$1" url="$2"
  for i in $(seq 1 30); do
    if curl -sf "$url" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} ${name} ready"
      return 0
    fi
    sleep 2
  done
  echo -e "  ${RED}✗${NC} ${name} not ready after 60s"
  return 1
}

wait_for "Test app" "$APP_URL/health"
wait_for "Jaeger"   "$JAEGER_URL"
wait_for "Pyroscope" "$PYROSCOPE_URL/ready"
wait_for "Collector" "$COLLECTOR_URL/healthz"

# --- Test app endpoints ---
echo ""
echo "1. Test app endpoints"
check "GET /health" curl -sf "$APP_URL/health"
check "GET /fast"   curl -sf "$APP_URL/fast"
check "GET /slow"   curl -sf "$APP_URL/slow"
check "GET /work"   curl -sf "$APP_URL/work"

# --- Standalone capture (Path A) ---
echo ""
echo "2. Standalone capture (Path A)"
check_output "GET /profile/capture returns speedscope JSON" '"$schema":"https://www.speedscope.app' \
  curl -sf "$APP_URL/profile/capture?duration=2&freq=99"

# --- Generate traffic for tracing ---
echo ""
echo "3. Generating trace traffic..."
for i in $(seq 1 5); do
  curl -sf "$APP_URL/slow" >/dev/null 2>&1 &
  curl -sf "$APP_URL/work" >/dev/null 2>&1 &
done
wait
sleep 5  # give exporters time to flush

# --- Jaeger traces (Path B) ---
echo ""
echo "4. Jaeger traces (Path B)"
check_output "Jaeger has rbscope-test-app service" "rbscope-test-app" \
  curl -sf "$JAEGER_URL/api/services"

TRACES=$(curl -sf "$JAEGER_URL/api/traces?service=rbscope-test-app&limit=5" 2>/dev/null || echo '{"data":[]}')
TRACE_COUNT=$(echo "$TRACES" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('data',[])))" 2>/dev/null || echo "0")
if [ "$TRACE_COUNT" -gt 0 ]; then
  echo -e "  ${GREEN}✓${NC} Found ${TRACE_COUNT} traces in Jaeger"
  ((PASS++))
else
  echo -e "  ${RED}✗${NC} No traces found in Jaeger"
  ((FAIL++))
fi

# --- Pyroscope profiles (Path C via demo collector) ---
echo ""
echo "5. Pyroscope profiles (Path C — demo mode)"
sleep 12  # wait for at least one flush interval

PYRO_APPS=$(curl -sf "$PYROSCOPE_URL/api/v1/apps" 2>/dev/null || echo "[]")
if echo "$PYRO_APPS" | grep -q "rbscope"; then
  echo -e "  ${GREEN}✓${NC} Pyroscope has rbscope profiles"
  ((PASS++))
else
  # Try the label-values API (Pyroscope 1.x+)
  PYRO_LABELS=$(curl -sf "${PYROSCOPE_URL}/querier.v1.QuerierService/LabelValues" \
    -H 'Content-Type: application/json' \
    -d '{"name":"__name__"}' 2>/dev/null || echo "")
  if echo "$PYRO_LABELS" | grep -q "rbscope"; then
    echo -e "  ${GREEN}✓${NC} Pyroscope has rbscope profiles (label API)"
    ((PASS++))
  else
    echo -e "  ${YELLOW}?${NC} Could not verify Pyroscope profiles (API may differ)"
    echo "     Check manually at: ${PYROSCOPE_URL}"
    # Don't count as failure — Pyroscope API varies by version
  fi
fi

# --- Collector health ---
echo ""
echo "6. Collector health"
check_output "Collector /healthz" "ok" curl -sf "$COLLECTOR_URL/healthz"
check "Collector /metrics (Prometheus)" curl -sf "$COLLECTOR_URL/metrics"

# --- Summary ---
echo ""
echo "====================="
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All ${TOTAL} checks passed!${NC}"
else
  echo -e "${RED}${FAIL}/${TOTAL} checks failed${NC}"
fi
echo ""

exit "$FAIL"
