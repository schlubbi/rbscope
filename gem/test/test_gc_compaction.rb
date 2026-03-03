# frozen_string_literal: true

require "test_helper"

class TestGcCompaction < Minitest::Test
  include Rbscope::TestHelper

  def test_profiling_survives_gc_compact
    skip "GC.compact not available" unless GC.respond_to?(:compact)

    Rbscope.start(frequency: 999)

    # Allocate objects, compact, verify profiler still works
    arrays = 1000.times.map { Array.new(100) { Object.new } }
    GC.compact
    arrays.clear
    GC.start

    busy_wait(0.1)
    count = Rbscope.stop
    assert count > 0, "profiler should survive GC compaction"
  end

  def test_profiling_with_gc_stress
    Rbscope.start(frequency: 1) # Low freq: callback allocates strings, each triggers GC

    # Run with GC stress to maximize chance of catching stale pointers
    old_stress = GC.stress
    GC.stress = true

    100.times { "x" * 1000 }

    GC.stress = old_stress

    count = Rbscope.stop
    assert count >= 0, "profiler should not crash under GC stress"
  end
end
