# frozen_string_literal: true

require_relative "config/application"

# Configure OpenTelemetry if the SDK is available
if OTEL_AVAILABLE
  OpenTelemetry::SDK.configure do |c|
    c.service_name = "rbscope-test-app"

    # OTLP exporter sends traces to OTel Collector (or Jaeger direct)
    c.add_span_processor(
      OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(
        OpenTelemetry::Exporter::OTLP::Exporter.new
      )
    )

    # Also add the rbscope span exporter (fires USDT probes)
    c.add_span_processor(
      OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(
        Rbscope::OTelExporter.new
      )
    )
  end

  $stderr.puts "[rbscope] OTel configured — traces → #{ENV.fetch("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")}"
else
  $stderr.puts "[rbscope] OTel SDK not available — running without trace export"
end

# Configure Pyroscope for continuous flame graphs
if PYROSCOPE_AVAILABLE
  Pyroscope.configure do |config|
    config.application_name = "rbscope-test-app"
    config.server_address = ENV.fetch("PYROSCOPE_SERVER_ADDRESS", "http://localhost:4040")
    config.tags = {
      "service" => "rbscope-test-app",
      "env" => "development"
    }
  end

  $stderr.puts "[rbscope] Pyroscope configured — profiles → #{ENV.fetch("PYROSCOPE_SERVER_ADDRESS", "http://localhost:4040")}"
else
  $stderr.puts "[rbscope] Pyroscope gem not available — running without continuous profiling"
end

run TestApp.new
