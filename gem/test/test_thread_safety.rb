# frozen_string_literal: true

require "test_helper"

class TestThreadSafety < Minitest::Test
  include Rbscope::TestHelper

  def test_concurrent_sampling_with_many_threads
    Rbscope.start(frequency: 999)

    threads = 50.times.map do |i|
      Thread.new do
        # Each thread does some work to generate different stacks
        1000.times { |n| Math.sqrt(n + i) }
      end
    end

    threads.each(&:join)
    count = Rbscope.stop

    assert count > 0, "should capture samples during multi-threaded execution"
  end

  def test_start_stop_from_multiple_threads
    # Concurrent start/stop shouldn't crash
    errors = []
    threads = 10.times.map do
      Thread.new do
        5.times do
          begin
            Rbscope.start(frequency: 99)
            busy_wait(0.01)
            Rbscope.stop
          rescue => e
            errors << e
          end
        end
      end
    end

    threads.each(&:join)

    # We don't assert on exact behavior (race conditions are expected),
    # but there should be no crashes or exceptions.
    assert errors.empty?, "concurrent start/stop should not raise: #{errors.map(&:message)}"
  ensure
    Rbscope.stop rescue nil
  end

  def test_profiling_during_thread_spawn_and_death
    Rbscope.start(frequency: 999)

    # Continuously spawn and kill threads while sampling
    20.times do
      t = Thread.new { busy_wait(0.01) }
      busy_wait(0.005)
      t.join
    end

    count = Rbscope.stop
    assert count > 0
  end
end
