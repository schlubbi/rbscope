# frozen_string_literal: true

require "test_helper"

class TestSampling < Minitest::Test
  include Rbscope::TestHelper

  def test_start_and_stop
    assert Rbscope.start(frequency: 99)
    assert Rbscope.enabled?

    count = Rbscope.stop
    assert_kind_of Integer, count
    refute Rbscope.enabled?
  end

  def test_stop_when_not_running
    count = Rbscope.stop
    assert_equal 0, count
  end

  def test_double_start_returns_false
    assert Rbscope.start(frequency: 99)
    refute Rbscope.start(frequency: 99) # already running
    Rbscope.stop
  end

  def test_invalid_frequency_zero
    assert_raises(ArgumentError) { Rbscope.start(frequency: 0) }
  end

  def test_invalid_frequency_too_high
    assert_raises(ArgumentError) { Rbscope.start(frequency: 100_000) }
  end

  def test_samples_accumulate
    Rbscope.start(frequency: 999)
    sleep 0.1
    count1 = Rbscope.sample_count
    sleep 0.1
    count2 = Rbscope.sample_count
    Rbscope.stop

    assert count2 > count1, "samples should accumulate over time"
  end

  def test_sample_count_at_99hz
    Rbscope.start(frequency: 99)
    sleep 1.0
    count = Rbscope.stop

    assert_samples_in_range(count, frequency: 99, duration: 1.0)
  end

  def test_sample_count_at_19hz
    Rbscope.start(frequency: 19)
    sleep 1.0
    count = Rbscope.stop

    assert_samples_in_range(count, frequency: 19, duration: 1.0)
  end

  def test_profile_block
    count = Rbscope.profile(frequency: 999) do
      sleep 0.5
    end

    assert count > 0, "profile block should capture samples"
  end

  def test_profile_block_stops_on_exception
    assert_raises(RuntimeError) do
      Rbscope.profile(frequency: 99) do
        raise "boom"
      end
    end

    refute Rbscope.enabled?, "profiler should be stopped after exception"
  end

  def test_restart_after_stop
    Rbscope.start(frequency: 99)
    sleep 0.05
    Rbscope.stop

    Rbscope.start(frequency: 99)
    sleep 0.05
    count = Rbscope.stop
    assert count > 0, "profiler should work after restart"
  end
end
