# frozen_string_literal: true

require "test_helper"

class TestDynamicRate < Minitest::Test
  include Rbscope::TestHelper

  def test_sampling_stats_returns_hash
    Rbscope.start(frequency: 99)
    busy_wait(0.2)
    stats = Rbscope.sampling_stats
    Rbscope.stop

    assert_kind_of Hash, stats
    assert_includes stats, :frequency_hz
    assert_includes stats, :avg_sample_ns
    assert_includes stats, :sample_count
    assert_includes stats, :max_frequency_hz
    assert_includes stats, :cache_hit_count
    assert_equal 99, stats[:max_frequency_hz]
  end

  def test_dynamic_rate_adapts_frequency
    Rbscope.start(frequency: 99, overhead_target: 0.02, dynamic_rate: true)
    busy_wait(1.0)
    stats = Rbscope.sampling_stats
    Rbscope.stop

    # Frequency should be positive and <= max
    assert stats[:frequency_hz] > 0, "frequency should be positive"
    assert stats[:frequency_hz] <= 99, "frequency should not exceed max"
    assert stats[:avg_sample_ns] > 0, "avg_sample_ns should be measured"
    assert stats[:sample_count] > 0, "should have captured samples"
  end

  def test_dynamic_rate_disabled_holds_fixed
    Rbscope.start(frequency: 99, dynamic_rate: false)
    busy_wait(0.5)
    stats = Rbscope.sampling_stats
    Rbscope.stop

    # With dynamic rate off, frequency should stay near configured rate
    # (within rounding tolerance since interval_ns → Hz is integer division)
    assert stats[:frequency_hz] >= 90, "fixed rate should stay near 99Hz, got #{stats[:frequency_hz]}"
  end

  def test_overhead_target_validation
    assert_raises(ArgumentError) { Rbscope.start(overhead_target: 0.0) }
    assert_raises(ArgumentError) { Rbscope.start(overhead_target: 1.0) }
  end

  def test_profile_with_dynamic_rate
    count = Rbscope.profile(frequency: 99, overhead_target: 0.01) do
      busy_wait(0.5)
    end

    assert count > 0, "profile with dynamic rate should capture samples"
  end

  def test_stats_reset_on_restart
    Rbscope.start(frequency: 99)
    busy_wait(0.2)
    Rbscope.stop

    Rbscope.start(frequency: 49)
    busy_wait(0.1)
    stats = Rbscope.sampling_stats
    Rbscope.stop

    assert_equal 49, stats[:max_frequency_hz]
  end
end
