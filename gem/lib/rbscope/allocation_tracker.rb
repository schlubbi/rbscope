# frozen_string_literal: true

module Rbscope
  # Tracks Ruby object allocations via native RUBY_INTERNAL_EVENT_NEWOBJ hook.
  #
  # Samples every Nth allocation and fires the ruby_alloc USDT probe
  # with the allocation type, size, and Ruby call stack. The eBPF
  # collector receives these as RubyAllocEvents.
  #
  # Usage:
  #   tracker = Rbscope::AllocationTracker.new(sample_interval: 256)
  #   tracker.start
  #   # ... your code ...
  #   count = tracker.stop
  #
  class AllocationTracker
    # @param sample_interval [Integer] track every Nth allocation (default: 256)
    def initialize(sample_interval: 256)
      @sample_interval = [sample_interval, 1].max
    end

    # Start tracking allocations.
    def start
      Native.start_allocation_tracking(@sample_interval)
    end

    # Stop tracking and return the number of sampled allocations.
    #
    # @return [Integer] number of sampled allocations
    def stop
      Native.stop_allocation_tracking
    end

    # Check if allocation tracking is active.
    def running?
      Native.allocation_tracking_enabled?
    end

    # Return allocation statistics.
    #
    # @return [Hash] with keys :total, :sampled, :sample_interval
    def stats
      total, sampled, interval = Native.allocation_stats
      { total: total, sampled: sampled, sample_interval: interval }
    end
  end
end
