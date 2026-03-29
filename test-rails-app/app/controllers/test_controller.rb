# frozen_string_literal: true

# Endpoints that simulate realistic Rails workloads for profiling.
class TestController < ApplicationController
  # GET /health — liveness probe
  def health
    # Also verify DB connectivity
    ActiveRecord::Base.connection.execute("SELECT 1")
    render plain: "healthy"
  end

  # GET /rbscope_status — diagnostics for rbscope state in this worker
  def rbscope_status
    if defined?(Rbscope)
      render json: {
        enabled: Rbscope.enabled?,
        gvl_profiling: Rbscope.gvl_profiling?,
        stats: Rbscope.sampling_stats,
        pid: Process.pid
      }
    else
      render json: { error: "rbscope not loaded" }
    end
  end

  # GET /fast — ~1ms baseline response
  def fast
    render plain: "ok"
  end

  # GET /slow — simulates I/O-heavy request (DB + cache + render)
  def slow
    Post.published.recent.limit(10).load  # DB query
    sleep 0.05                             # simulated cache/external call
    sleep 0.1                              # simulated template render
    render plain: "slow ok"
  end

  # GET /allocate — allocates 10k objects (tests allocation tracker / GC pressure)
  def allocate
    objects = 10_000.times.map { Object.new }
    render plain: "allocated #{objects.size} objects"
  end

  # GET /work — CPU-bound Fibonacci (shows up clearly in flame graphs)
  def work
    result = fibonacci(32)
    render plain: "fib(32) = #{result}"
  end

  private

  def fibonacci(n)
    return n if n <= 1
    fibonacci(n - 1) + fibonacci(n - 2)
  end
end
