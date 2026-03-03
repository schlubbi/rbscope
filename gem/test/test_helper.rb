# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "rbscope"
require "minitest/autorun"

# Enable GC compaction to catch stale pointer bugs in the native extension.
GC.auto_compact = true if GC.respond_to?(:auto_compact=)

module Rbscope
  module TestHelper
    # Assert that profiling captured a reasonable number of samples
    # given the frequency and duration.
    def assert_samples_in_range(count, frequency:, duration:, tolerance: 0.5)
      expected = frequency * duration
      min = (expected * (1.0 - tolerance)).floor
      max = (expected * (1.0 + tolerance)).ceil
      assert count >= min && count <= max,
             "Expected #{min}-#{max} samples (#{frequency}Hz × #{duration}s), got #{count}"
    end

    # Busy-wait for the given duration while doing Ruby work.
    # This keeps the Ruby VM active at safe points so postponed job
    # callbacks (used by the real sampling engine) can fire.
    def busy_wait(seconds)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
      i = 0
      while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        i += 1
        Math.sqrt(i)
      end
    end

    # Ensure the profiler is stopped after each test.
    def teardown
      Rbscope.stop if Rbscope.enabled?
      super
    end
  end
end
