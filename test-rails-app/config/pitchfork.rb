# Pitchfork configuration for rbscope test app.
# Pitchfork is a preforking HTTP server — each worker is a forked process.
# This exercises rbscope's fork safety and multi-process profiling.
#
# Unlike Unicorn, Pitchfork always preloads the app (no preload_app option).

worker_processes 2
timeout 30

listen "0.0.0.0:3000"

# Refork workers periodically to benefit from CoW after warmup
refork_after [50, 100, 1000]

after_worker_fork do |_server, worker|
  # Each worker reconnects to MySQL
  ActiveRecord::Base.establish_connection if defined?(ActiveRecord::Base)

  # Re-initialize rbscope sampling in the child process
  if defined?(Rbscope) && ENV["RBSCOPE"] == "1"
    Rbscope.start
  end
end
