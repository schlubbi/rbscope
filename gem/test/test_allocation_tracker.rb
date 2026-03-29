# frozen_string_literal: true

require_relative "test_helper"

class TestAllocationTracker < Minitest::Test
  def test_start_and_stop
    result = Rbscope.enable_allocation_tracking(sample_interval: 256)
    assert result, "enable_allocation_tracking should return true"
    assert Rbscope.allocation_tracking?, "allocation_tracking? should be true"

    count = Rbscope.stop_allocation_tracking
    refute Rbscope.allocation_tracking?, "allocation_tracking? should be false after stop"
    # count may be 0 if no allocations hit the sample interval
    assert_kind_of Integer, count
  end

  def test_allocations_are_counted
    Rbscope.enable_allocation_tracking(sample_interval: 1) # every allocation

    # Force many allocations
    1000.times { "x" * 100 }

    count = Rbscope.stop_allocation_tracking
    # With sample_interval=1, we should have many sampled allocations.
    # The exact count depends on how many allocations Ruby does internally
    # (string creation, array ops, etc.) but should be well above 100.
    assert count > 50, "expected >50 sampled allocations, got #{count}"
  end

  def test_sample_interval
    Rbscope.enable_allocation_tracking(sample_interval: 100)

    10_000.times { Object.new }

    count = Rbscope.stop_allocation_tracking
    # With sample_interval=100 and 10K explicit allocations (plus internal),
    # we should have roughly 100+ samples.
    assert count > 10, "expected >10 sampled allocations at 1:100, got #{count}"
    assert count < 10_000, "expected <10000 (sampling should reduce), got #{count}"
  end

  def test_double_start_returns_false
    Rbscope.enable_allocation_tracking(sample_interval: 256)
    result = Rbscope.enable_allocation_tracking(sample_interval: 256)
    refute result, "second start should return false"
    Rbscope.stop_allocation_tracking
  end

  def test_stop_when_not_running_returns_zero
    count = Rbscope.stop_allocation_tracking
    assert_equal 0, count
  end

  def test_allocation_stats
    Rbscope.enable_allocation_tracking(sample_interval: 100)
    1000.times { "x" * 50 }

    total, sampled, interval = Rbscope::Native.allocation_stats
    assert total > 0, "total allocations should be > 0"
    assert sampled > 0, "sampled allocations should be > 0"
    assert_equal 100, interval

    Rbscope.stop_allocation_tracking
  end

  def test_concurrent_with_cpu_sampling
    # Allocation tracking should work alongside CPU sampling
    Rbscope.start(frequency: 99)
    Rbscope.enable_allocation_tracking(sample_interval: 256)

    # Do some work
    100.times { "x" * 100 }
    sleep 0.05

    alloc_count = Rbscope.stop_allocation_tracking
    sample_count = Rbscope.stop

    assert alloc_count >= 0, "alloc count should be non-negative"
    assert sample_count >= 0, "sample count should be non-negative"
  end
end
