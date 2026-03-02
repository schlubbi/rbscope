# frozen_string_literal: true

require "test_helper"

class TestForkSafety < Minitest::Test
  include Rbscope::TestHelper

  def test_fork_while_sampling
    skip "fork not available" unless Process.respond_to?(:fork)

    Rbscope.start(frequency: 99)
    sleep 0.05

    pid = fork do
      # In child: profiler should not be running (quiesced on fork)
      # Starting fresh should work
      sleep 0.05
      exit!(0)
    end

    # Parent: continue sampling
    sleep 0.1
    _status = Process.wait2(pid)
    count = Rbscope.stop

    assert count > 0, "parent should still be sampling after fork"
  end

  def test_restart_in_child_after_fork
    skip "fork not available" unless Process.respond_to?(:fork)

    Rbscope.start(frequency: 99)
    sleep 0.02

    rd, wr = IO.pipe

    pid = fork do
      rd.close
      # Child: start a fresh profiler
      Rbscope.start(frequency: 99)
      sleep 0.1
      count = Rbscope.stop
      wr.write(count.to_s)
      wr.close
      exit!(0)
    end

    wr.close
    Process.wait(pid)
    child_count = rd.read.to_i
    rd.close

    parent_count = Rbscope.stop
    assert parent_count > 0, "parent profiler should work"
    assert child_count > 0, "child profiler should work after restart"
  end
end
