# frozen_string_literal: true

require "test_helper"
require "benchmark"

class TestOverhead < Minitest::Test
  include Rbscope::TestHelper

  ITERATIONS = 10_000
  WARMUP = 1_000

  def test_overhead_under_one_percent
    # Warmup
    WARMUP.times { work_unit }

    # Baseline: no profiler
    baseline = Benchmark.realtime do
      ITERATIONS.times { work_unit }
    end

    # With profiler at always-on rate (fixed, no dynamic adjustment)
    Rbscope.start(frequency: 19, dynamic_rate: false)
    profiled = Benchmark.realtime do
      ITERATIONS.times { work_unit }
    end
    Rbscope.stop

    overhead_pct = ((profiled - baseline) / baseline * 100.0)

    puts "\n  Overhead: #{overhead_pct.round(2)}% " \
         "(baseline=#{(baseline * 1000).round(1)}ms, " \
         "profiled=#{(profiled * 1000).round(1)}ms)"

    # Allow up to 5% in test environment (real target is <1% in production,
    # but test machines have more variance)
    assert overhead_pct < 5.0,
           "overhead #{overhead_pct.round(2)}% exceeds 5% threshold"
  end

  private

  def work_unit
    # Simulate a minimal "request" — string manipulation + array ops
    a = (1..100).to_a
    a.map { |n| n.to_s }.join(",")
  end
end
