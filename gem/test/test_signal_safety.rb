# frozen_string_literal: true

require "test_helper"

class TestSignalSafety < Minitest::Test
  include Rbscope::TestHelper

  def test_sigint_during_sampling
    skip "signals not reliable in CI" if ENV["CI"]

    Rbscope.start(frequency: 99)
    sleep 0.05

    # Send SIGINT to ourselves — profiler should handle it gracefully
    old_handler = trap("INT") { } # no-op handler
    Process.kill("INT", Process.pid)
    sleep 0.05

    count = Rbscope.stop
    assert count > 0, "profiler should survive SIGINT"
  ensure
    trap("INT", old_handler) if old_handler
  end

  def test_clean_shutdown_under_load
    Rbscope.start(frequency: 999)

    # Generate heavy load
    threads = 10.times.map do
      Thread.new do
        10_000.times { "x" * 1000 }
      end
    end

    # Give sampler time to capture some samples
    sleep 0.1

    # Stop while threads are still working
    count = Rbscope.stop
    threads.each(&:join)

    assert count > 0, "should capture samples before stop"
    refute Rbscope.enabled?, "should be cleanly stopped"
  end
end
