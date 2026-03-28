# frozen_string_literal: true

require_relative "boot"

require "rails"
require "active_record/railtie"
require "action_controller/railtie"

module RbscopeTestApp
  class Application < Rails::Application
    config.load_defaults 8.1
    config.eager_load = false
    config.consider_all_requests_local = true
    config.secret_key_base = "rbscope-test-app-dev-secret-not-for-production"
    config.hosts.clear

    config.api_only = true

    # Log to stdout for Docker
    config.logger = ActiveSupport::Logger.new($stdout)
    config.log_level = :info

    # --- OTel setup ---
    # The standard OTel SDK generates traces (Rack → Rails → ActiveRecord)
    # and exports them via OTLP to the OTel Collector → Jaeger.
    #
    # rbscope's OTelExporter is a span processor that intercepts completed
    # spans and fires ruby_span USDT probes. The rbscope collector reads
    # those via BPF uprobes, correlating traces with CPU profiles.
    initializer "rbscope.otel", before: :build_middleware_stack do
      begin
        require "opentelemetry/sdk"
        require "opentelemetry-exporter-otlp"
        require "opentelemetry-instrumentation-rack"
        require "opentelemetry-instrumentation-rails"
        require "opentelemetry-instrumentation-active_record"

        OpenTelemetry::SDK.configure do |c|
          c.service_name = "rbscope-test-app"
          c.use "OpenTelemetry::Instrumentation::Rack"
          c.use "OpenTelemetry::Instrumentation::Rails"
          c.use "OpenTelemetry::Instrumentation::ActiveRecord"

          # Standard OTLP export → OTel Collector → Jaeger
          c.add_span_processor(
            OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(
              OpenTelemetry::Exporter::OTLP::Exporter.new
            )
          )

          # rbscope span processor: fires USDT probes for BPF collection
          begin
            require "rbscope/otel"
            c.add_span_processor(
              OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(
                Rbscope::OTelExporter.new
              )
            )
          rescue LoadError
            # rbscope native extension not compiled — skip
          end
        end

        # Insert OTel Rack tracing middleware at the top of the stack
        rack_inst = OpenTelemetry::Instrumentation::Rack::Instrumentation.instance
        config.middleware.insert_before(0, *rack_inst.middleware_args)
      rescue LoadError => e
        $stderr.puts "[rbscope] OTel not available: #{e.message}"
      end
    end
  end
end

Rails.application.initialize!

# --- rbscope profiling (after init so logger is available) ---
if ENV["RBSCOPE"] == "1"
  Rbscope.start(frequency: 99)
  Rails.logger.info "[rbscope] Profiling started at 99Hz (USDT probes active)"
end
