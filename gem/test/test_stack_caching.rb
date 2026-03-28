# frozen_string_literal: true

require "test_helper"

class TestStackCaching < Minitest::Test
  include Rbscope::TestHelper

  def test_cache_hits_during_tight_loop
    # A tight loop calling the same method should produce cache hits
    # because the stack is identical across consecutive samples.
    Rbscope.start(frequency: 999, dynamic_rate: false)

    # Do repetitive work — same call stack each iteration.
    # busy_wait keeps the VM active at safe points so samples fire.
    busy_wait(0.5)

    stats = Rbscope.sampling_stats
    Rbscope.stop

    assert stats[:sample_count] > 0, "should have captured samples"
    assert stats[:cache_hit_count] >= 0, "cache_hit_count should be non-negative"

    # With a tight loop at 999Hz, we expect significant cache hits
    # since the stack rarely changes between samples
    if stats[:sample_count] > 5
      assert stats[:cache_hit_count] > 0,
             "tight loop at 999Hz should produce cache hits " \
             "(samples=#{stats[:sample_count]}, hits=#{stats[:cache_hit_count]})"
    end
  end

  def test_cache_resets_on_restart
    Rbscope.start(frequency: 99, dynamic_rate: false)
    busy_wait(0.1)
    Rbscope.stop

    Rbscope.start(frequency: 99, dynamic_rate: false)
    stats = Rbscope.sampling_stats
    # Right after start, cache_hit_count should be 0
    assert_equal 0, stats[:cache_hit_count],
                 "cache_hit_count should reset on restart"
    Rbscope.stop
  end
end
