# frozen_string_literal: true

require "test_helper"

class TestAllocationTracker < Minitest::Test
  include Rbscope::TestHelper

  # The allocation tracker is a Ruby-level feature that uses TracePoint
  # to sample object allocations and fire the ruby_alloc USDT probe.
  # Phase 1 implements the Ruby wrapper; real USDT firing comes in Phase 1.2.

  def test_track_allocations
    tracker = Rbscope::AllocationTracker.new(sample_interval: 1)
    tracker.start

    # Allocate some objects
    100.times { Object.new }

    count = tracker.stop
    assert count > 0, "should track allocations (got #{count})"
  end

  def test_sampled_tracking
    # With interval=10, we should see ~1/10th of allocations
    tracker = Rbscope::AllocationTracker.new(sample_interval: 10)
    tracker.start

    1000.times { Object.new }

    count = tracker.stop
    # Allow wide tolerance — GC and internal allocations make exact counts hard
    assert count >= 10, "should track sampled allocations (got #{count})"
    assert count <= 500, "should not track every allocation (got #{count})"
  end

  def test_default_interval
    tracker = Rbscope::AllocationTracker.new
    tracker.start
    100.times { Object.new }
    count = tracker.stop
    assert count >= 0
  end

  def test_stop_when_not_started
    tracker = Rbscope::AllocationTracker.new
    count = tracker.stop
    assert_equal 0, count
  end

  def test_double_start
    tracker = Rbscope::AllocationTracker.new(sample_interval: 1)
    tracker.start
    tracker.start # should not raise
    10.times { Object.new }
    tracker.stop
  end

  def test_tracks_different_types
    tracker = Rbscope::AllocationTracker.new(sample_interval: 1)
    tracker.start

    # Allocate various types
    50.times { String.new("x") }
    50.times { Array.new }
    50.times { Hash.new }

    count = tracker.stop
    assert count > 0
  end
end
