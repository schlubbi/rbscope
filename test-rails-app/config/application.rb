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
  end
end

Rails.application.initialize!

# --- OTel setup ---
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

    c.add_span_processor(
      OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(
        OpenTelemetry::Exporter::OTLP::Exporter.new
      )
    )

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

  Rails.logger.info "[rbscope] OTel configured — traces → #{ENV.fetch("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")}"
rescue LoadError => e
  Rails.logger.info "[rbscope] OTel not available: #{e.message}"
end
