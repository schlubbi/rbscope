# Pitchfork configuration for rbscope test app.
# Pitchfork is a preforking HTTP server — each worker is a forked process.
# This exercises rbscope's fork safety and multi-process profiling.
#
# Unlike Unicorn, Pitchfork always preloads the app (no preload_app option).

worker_processes 2
timeout 30

listen "0.0.0.0:3000"

# Disable reforking in dev — it churns workers too frequently for the
# collector to maintain stable uprobe attachments.
# In production you'd enable: refork_after [1000, 5000]

after_worker_fork do |_server, worker|
  # Each worker reconnects to MySQL
  ActiveRecord::Base.establish_connection if defined?(ActiveRecord::Base)

  # Re-initialize rbscope sampling in the child process
  if defined?(Rbscope) && ENV["RBSCOPE"] == "1"
    Rbscope.start
    Rbscope.enable_gvl_profiling
  end
end
