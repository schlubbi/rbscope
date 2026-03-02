# frozen_string_literal: true

require_relative "rbscope/version"
require_relative "rbscope/rbscope"
require_relative "rbscope/allocation_tracker"
require_relative "rbscope/capture"

# Rbscope — Ruby X-ray Profiling
#
# A modern, always-on Ruby profiler that emits USDT probes for external
# eBPF-based collection. Successor to tracecap by Theo Julienne.
#
# Usage:
#   require "rbscope"
#   Rbscope.start(frequency: 99)
#   # ... your code ...
#   result = Rbscope.stop
#   puts "Captured #{result} samples"
#
module Rbscope
  class Error < StandardError; end

  # Start profiling at the given frequency.
  #
  # @param frequency [Integer] Sampling rate in Hz
  #   - 19:  always-on (minimal overhead)
  #   - 99:  standard profiling
  #   - 999: deep capture
  # @return [Boolean] true if started, false if already running
  def self.start(frequency: 99)
    Native.start_sampling(frequency)
  end

  # Stop profiling and return the number of samples captured.
  #
  # @return [Integer] number of samples captured
  def self.stop
    Native.stop_sampling
  end

  # Check if the profiler is currently running.
  #
  # @return [Boolean]
  def self.enabled?
    Native.enabled?
  end

  # Return the number of samples captured so far.
  #
  # @return [Integer]
  def self.sample_count
    Native.sample_count
  end

  # Profile a block of code.
  #
  # @param frequency [Integer] Sampling rate in Hz
  # @yield The block to profile
  # @return [Integer] number of samples captured
  def self.profile(frequency: 99)
    start(frequency: frequency)
    yield
    stop
  rescue => e
    stop
    raise e
  end
end
