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
  # @param frequency [Integer] Sampling rate in Hz (max frequency when dynamic rate is on)
  #   - 19:  always-on (minimal overhead)
  #   - 99:  standard profiling
  #   - 999: deep capture
  # @param overhead_target [Float] Max CPU overhead (0.0-0.5, default 0.02 = 2%)
  # @param dynamic_rate [Boolean] Enable adaptive frequency (default true)
  # @return [Boolean] true if started, false if already running
  def self.start(frequency: 99, overhead_target: 0.02, dynamic_rate: true)
    Native.set_overhead_target(overhead_target)
    Native.set_dynamic_rate(dynamic_rate)
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
  # @param overhead_target [Float] Max CPU overhead
  # @param dynamic_rate [Boolean] Enable adaptive frequency
  # @yield The block to profile
  # @return [Integer] number of samples captured
  def self.profile(frequency: 99, overhead_target: 0.02, dynamic_rate: true)
    start(frequency: frequency, overhead_target: overhead_target, dynamic_rate: dynamic_rate)
    yield
    stop
  rescue => e
    stop
    raise e
  end

  # Return current sampling statistics.
  #
  # @return [Hash] with keys :frequency_hz, :avg_sample_ns, :sample_count, :max_frequency_hz
  def self.sampling_stats
    freq, avg_ns, count, max_freq = Native.sampling_stats
    {
      frequency_hz: freq,
      avg_sample_ns: avg_ns,
      sample_count: count,
      max_frequency_hz: max_freq
    }
  end
end
