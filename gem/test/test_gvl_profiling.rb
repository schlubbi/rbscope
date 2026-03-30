# frozen_string_literal: true

require_relative "test_helper"

class TestGVLProfiling < Minitest::Test
  def test_enable_gvl_profiling
    assert Rbscope.enable_gvl_profiling, "enable_gvl_profiling should return true"
    assert Rbscope.gvl_profiling?, "gvl_profiling? should be true after enabling"
  end

  def test_enable_gvl_profiling_idempotent
    Rbscope.enable_gvl_profiling
    assert Rbscope.enable_gvl_profiling, "second call should also return true"
  end

  def test_gvl_events_fire_under_contention
    Rbscope.enable_gvl_profiling

    initial_count = Rbscope::Native.gvl_event_count

    # Create GVL contention: multiple threads doing CPU work
    threads = 4.times.map do
      Thread.new do
        # Pure CPU work that requires the GVL
        sum = 0
        10_000.times { |i| sum += i }
        sum
      end
    end
    threads.each(&:join)

    final_count = Rbscope::Native.gvl_event_count

    # With 4 threads competing for GVL, we should see events.
    # The exact count depends on scheduling, but > 0 is expected.
    assert final_count > initial_count,
      "expected GVL events to fire under contention " \
      "(initial: #{initial_count}, final: #{final_count})"
  end

  def test_sampling_stats_includes_gvl
    Rbscope.enable_gvl_profiling
    stats = Rbscope.sampling_stats
    assert stats.key?(:gvl_event_count), "sampling_stats should include :gvl_event_count"
    assert_kind_of Integer, stats[:gvl_event_count]
  end
end
