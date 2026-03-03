# frozen_string_literal: true

require "rbscope"

begin
  require "opentelemetry-sdk"
rescue LoadError
  # OTel not available — the exporter won't be usable but the gem
  # can still be loaded for basic profiling without OTel integration.
end

module Rbscope
  # OpenTelemetry SpanExporter that fires the ruby_span USDT probe
  # for each completed span, attaching the current Ruby stack.
  #
  # This replaces tracecap-ruby-opentelemetry by exporting span context
  # through USDT probes for external eBPF collection.
  #
  # Usage:
  #   OpenTelemetry::SDK.configure do |c|
  #     c.add_span_processor(
  #       OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(
  #         Rbscope::OTelExporter.new
  #       )
  #     )
  #   end
  #
  class OTelExporter
    SUCCESS = begin
      OpenTelemetry::SDK::Trace::Export::SUCCESS
    rescue NameError
      0
    end

    FAILURE = begin
      OpenTelemetry::SDK::Trace::Export::FAILURE
    rescue NameError
      1
    end

    attr_reader :spans_exported

    def initialize
      @spans_exported = 0
      @shutdown = false
    end

    # Called by the OTel SDK for each batch of completed spans.
    #
    # For each span, we fire the ruby_span USDT probe with:
    #   - trace_id (16 bytes)
    #   - span_id (8 bytes)
    #   - operation name
    #   - duration in nanoseconds
    #   - current Ruby stack (serialized)
    #
    # @param span_datas [Array<OpenTelemetry::SDK::Trace::SpanData>]
    # @return [Integer] SUCCESS or FAILURE
    def export(span_datas, timeout: nil)
      return FAILURE if @shutdown

      span_datas.each do |span_data|
        export_span(span_data)
        @spans_exported += 1
      end

      SUCCESS
    rescue => e
      warn "[rbscope] OTelExporter error: #{e.message}"
      FAILURE
    end

    # Called when the SDK shuts down.
    def shutdown(timeout: nil)
      @shutdown = true
      SUCCESS
    end

    # Called on force-flush requests.
    def force_flush(timeout: nil)
      SUCCESS
    end

    private

    def export_span(span_data)
      trace_id = span_data.hex_trace_id
      span_id = span_data.hex_span_id
      operation = span_data.name
      duration_ns = ((span_data.end_timestamp - span_data.start_timestamp) * 1_000_000_000).to_i

      Rbscope::Native.fire_span(trace_id, span_id, operation, duration_ns)
    end
  end
end
