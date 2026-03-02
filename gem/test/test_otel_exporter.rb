# frozen_string_literal: true

require "test_helper"

# Test the OTel exporter with a mock SpanData.
class TestOtelExporter < Minitest::Test
  include Rbscope::TestHelper

  # Minimal mock that quacks like OpenTelemetry::SDK::Trace::SpanData
  MockSpanData = Struct.new(
    :hex_trace_id, :hex_span_id, :name,
    :start_timestamp, :end_timestamp,
    keyword_init: true
  )

  def setup
    require "rbscope/otel"
  end

  def test_export_returns_success
    exporter = Rbscope::OTelExporter.new
    spans = [mock_span("GET /users", duration_ms: 150)]

    result = exporter.export(spans)
    assert_equal Rbscope::OTelExporter::SUCCESS, result
    assert_equal 1, exporter.spans_exported
  end

  def test_export_multiple_spans
    exporter = Rbscope::OTelExporter.new
    spans = 10.times.map { |i| mock_span("op-#{i}", duration_ms: i * 10) }

    exporter.export(spans)
    assert_equal 10, exporter.spans_exported
  end

  def test_shutdown_rejects_further_exports
    exporter = Rbscope::OTelExporter.new
    exporter.shutdown

    result = exporter.export([mock_span("late")])
    assert_equal Rbscope::OTelExporter::FAILURE, result
    assert_equal 0, exporter.spans_exported
  end

  def test_force_flush_succeeds
    exporter = Rbscope::OTelExporter.new
    assert_equal Rbscope::OTelExporter::SUCCESS, exporter.force_flush
  end

  def test_export_with_zero_duration
    exporter = Rbscope::OTelExporter.new
    span = mock_span("instant", duration_ms: 0)
    result = exporter.export([span])
    assert_equal Rbscope::OTelExporter::SUCCESS, result
  end

  private

  def mock_span(name, duration_ms: 100)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    MockSpanData.new(
      hex_trace_id: "a" * 32,
      hex_span_id: "b" * 16,
      name: name,
      start_timestamp: now,
      end_timestamp: now + (duration_ms / 1000.0)
    )
  end
end
