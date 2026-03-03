# Loaded via RUBYOPT to enable rbscope profiling for any Ruby process.
# The collector (with BPF) runs separately and attaches via uprobe.
$LOAD_PATH.unshift("/workspaces/rbscope/gem/lib")
require "rbscope"
Rbscope.start(frequency: 99)

# Wire rbscope as an OTel span exporter so span events flow through
# the USDT probe → BPF → collector → Jaeger pipeline.
begin
  require "rbscope/otel"
  if defined?(OpenTelemetry::SDK)
    OpenTelemetry::SDK.configure do |c|
      c.add_span_processor(
        OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(
          Rbscope::OTelExporter.new
        )
      )
    end
  end
rescue LoadError
  # opentelemetry-sdk not available; profiling-only mode
end

# Re-start rbscope in forked workers (pitchfork, unicorn, etc.).
# After fork, the sampler thread is gone and probes are disabled.
# Prepend Process._fork (Ruby 3.1+) to auto-restart in children.
module RbscopeForkRestart
  def _fork
    pid = super
    if pid == 0
      # Child process: restart the sampler
      Rbscope.start(frequency: 99)
    end
    pid
  end
end
Process.singleton_class.prepend(RbscopeForkRestart)
