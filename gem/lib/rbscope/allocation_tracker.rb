# frozen_string_literal: true

module Rbscope
  # Tracks Ruby object allocations using TracePoint.
  #
  # Samples every Nth allocation and records it. In Phase 1.2,
  # each sampled allocation will fire the ruby_alloc USDT probe
  # with the allocation type, size, and Ruby stack.
  #
  # Usage:
  #   tracker = Rbscope::AllocationTracker.new(sample_interval: 100)
  #   tracker.start
  #   # ... your code ...
  #   count = tracker.stop
  #
  class AllocationTracker
    # @param sample_interval [Integer] track every Nth allocation (default: 100)
    def initialize(sample_interval: 100)
      @sample_interval = [sample_interval, 1].max
      @count = 0
      @total = 0
      @tracepoint = nil
      @running = false
    end

    # Start tracking allocations.
    def start
      return if @running

      @count = 0
      @total = 0
      @running = true

      @tracepoint = TracePoint.new(:c_call, :call) do |_tp|
        # TracePoint(:c_call) fires on C-level method calls which includes
        # allocation-heavy paths. We use a simple counter-based sampler.
        #
        # TODO(phase1.5): Switch to RUBY_INTERNAL_EVENT_NEWOBJ via the
        # native extension for precise allocation tracking. The Ruby-level
        # TracePoint approach works for now but has higher overhead and
        # doesn't catch all allocations.
        @total += 1
        if @total % @sample_interval == 0
          @count += 1
          # TODO(phase1.2): fire ruby_alloc USDT probe here
        end
      end

      @tracepoint.enable
    end

    # Stop tracking and return the number of sampled allocations.
    #
    # @return [Integer] number of sampled allocations
    def stop
      return 0 unless @running

      @tracepoint&.disable
      @tracepoint = nil
      @running = false
      @count
    end
  end
end
