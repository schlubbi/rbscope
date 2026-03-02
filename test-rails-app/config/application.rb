# frozen_string_literal: true

# Minimal Rack app for verifying rbscope probes and overhead.
#
# Endpoints:
#   GET /fast     — ~1ms response (baseline)
#   GET /slow     — 500ms sleep (simulates I/O)
#   GET /allocate — allocates 10k objects (tests allocation tracker)
#   GET /work     — CPU-bound Fibonacci (shows up in flame graphs)
#
# Profile control:
#   GET /profile/start?freq=99   — start sampling
#   GET /profile/stop            — stop, return sample count
#   GET /profile/status          — check if running
#
# Standalone capture (viewable output):
#   GET /profile/capture?duration=5&freq=99  — capture and return speedscope JSON
#   GET /profile/capture?duration=5&format=collapsed — flamegraph.pl format
#
# Run with: bundle exec puma -b tcp://0.0.0.0:3000

require "rbscope"
require "json"

# Optionally load OTel if available
OTEL_AVAILABLE = begin
  require "opentelemetry/sdk"
  require "opentelemetry-exporter-otlp"
  require "rbscope/otel"
  true
rescue LoadError => e
  $stderr.puts "[rbscope] OTel not available: #{e.message}"
  false
end

# Optionally load Pyroscope if available
PYROSCOPE_AVAILABLE = begin
  require "pyroscope"
  true
rescue LoadError
  false
end

class TestApp
  def call(env)
    if OTEL_AVAILABLE && defined?(OpenTelemetry::Trace)
      tracer = OpenTelemetry.tracer_provider.tracer("rbscope-test-app", "0.1.0")
      tracer.in_span("#{env["REQUEST_METHOD"]} #{env["PATH_INFO"]}",
                      attributes: { "http.method" => env["REQUEST_METHOD"],
                                    "http.target" => env["PATH_INFO"] }) do |span|
        status, headers, body = handle_request(env, tracer)
        span.set_attribute("http.status_code", status)
        [status, headers, body]
      end
    else
      handle_request(env, nil)
    end
  end

  private

  def handle_request(env, tracer)
    case env["PATH_INFO"]
    when "/fast"
      [200, { "content-type" => "text/plain" }, ["ok"]]

    when "/slow"
      with_span(tracer, "db.query", attributes: { "db.system" => "mysql", "db.statement" => "SELECT * FROM users" }) do
        sleep 0.2
      end
      with_span(tracer, "cache.read", attributes: { "cache.type" => "redis", "cache.key" => "user:123" }) do
        sleep 0.05
      end
      with_span(tracer, "render.template", attributes: { "template.name" => "users/show.html.erb" }) do
        sleep 0.1
      end
      [200, { "content-type" => "text/plain" }, ["slow ok"]]

    when "/allocate"
      objects = nil
      with_span(tracer, "allocate.objects", attributes: { "object.count" => 10_000 }) do
        objects = 10_000.times.map { Object.new }
      end
      with_span(tracer, "serialize.response") do
        sleep 0.01
      end
      [200, { "content-type" => "text/plain" }, ["allocated #{objects.size} objects"]]

    when "/work"
      result = nil
      with_span(tracer, "compute.fibonacci", attributes: { "fibonacci.n" => 32 }) do
        result = fibonacci(32)
      end
      with_span(tracer, "format.result") do
        sleep 0.001
      end
      [200, { "content-type" => "text/plain" }, ["fib(32) = #{result}"]]

    when "/health"
      [200, { "content-type" => "text/plain" }, ["healthy"]]

    # --- Profile control ---
    when "/profile/start"
      freq = parse_query(env)["freq"]&.to_i || 99
      Rbscope.start(frequency: freq)
      [200, { "content-type" => "text/plain" }, ["profiling at #{freq}Hz"]]
    when "/profile/stop"
      count = Rbscope.stop
      [200, { "content-type" => "text/plain" }, ["stopped, #{count} samples"]]
    when "/profile/status"
      body = "enabled=#{Rbscope.enabled?} samples=#{Rbscope.sample_count}"
      [200, { "content-type" => "text/plain" }, [body]]

    # --- Standalone capture with viewable output ---
    when "/profile/capture"
      params = parse_query(env)
      duration = (params["duration"] || "3").to_f
      freq = (params["freq"] || "99").to_i
      format = params["format"] || "speedscope"

      capture = Rbscope::Capture.new(frequency: freq)
      capture.start

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + duration
      while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        fibonacci(28)
        10_000.times { Object.new }
        sleep(0.01)
      end

      capture.stop

      case format
      when "collapsed"
        [200, { "content-type" => "text/plain",
                "content-disposition" => "attachment; filename=rbscope.collapsed" },
             [capture.to_collapsed]]
      else
        [200, { "content-type" => "application/json",
                "content-disposition" => "attachment; filename=rbscope.speedscope.json" },
             [capture.to_speedscope_json]]
      end

    else
      [404, { "content-type" => "text/plain" }, ["not found"]]
    end
  end

  def with_span(tracer, name, attributes: {})
    if tracer
      tracer.in_span(name, attributes: attributes) { yield }
    else
      yield
    end
  end

  def fibonacci(n)
    return n if n <= 1
    fibonacci(n - 1) + fibonacci(n - 2)
  end

  def parse_query(env)
    (env["QUERY_STRING"] || "").split("&").each_with_object({}) do |pair, h|
      k, v = pair.split("=", 2)
      h[k] = v if k
    end
  end
end
