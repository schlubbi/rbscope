# frozen_string_literal: true

module Rbscope
  # Standalone in-process stack capture for when no external eBPF
  # collector is attached. Produces a speedscope-compatible JSON file
  # that can be loaded at https://www.speedscope.app/
  #
  # Usage:
  #   capture = Rbscope::Capture.new(frequency: 99)
  #   capture.start
  #   # ... workload ...
  #   capture.stop
  #   File.write("profile.json", capture.to_speedscope_json)
  #
  class Capture
    attr_reader :sample_count, :duration_ms

    def initialize(frequency: 99)
      @frequency = frequency
      @interval = 1.0 / frequency
      @stacks = Hash.new(0) # "frame1;frame2;..." => count
      @running = false
      @thread = nil
      @sample_count = 0
      @start_time = nil
      @duration_ms = 0
    end

    def start
      return false if @running

      @running = true
      @stacks.clear
      @sample_count = 0
      @start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Also start the native sampler (for USDT probe path)
      Rbscope.start(frequency: @frequency)

      @thread = Thread.new do
        Thread.current.name = "rbscope-capture"
        capture_loop
      end

      true
    end

    def stop
      return 0 unless @running

      @running = false
      @thread&.join(2)
      @thread = nil
      @duration_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - @start_time) * 1000).round
      Rbscope.stop
      @sample_count
    end

    def to_speedscope_json
      frames = {}
      frame_list = []

      profiles = [{
        "type" => "sampled",
        "name" => "rbscope capture (#{@frequency}Hz, #{@duration_ms}ms)",
        "unit" => "none",
        "startValue" => 0,
        "endValue" => @sample_count,
        "samples" => [],
        "weights" => []
      }]

      @stacks.each do |stack_key, count|
        frame_names = stack_key.split(";")
        sample_frame_indices = frame_names.map do |name|
          unless frames.key?(name)
            idx = frame_list.size
            frames[name] = idx
            file, line, method = parse_frame(name)
            frame_list << { "name" => method || name, "file" => file, "line" => line }
          end
          frames[name]
        end

        profiles[0]["samples"] << sample_frame_indices
        profiles[0]["weights"] << count
      end

      JSON.generate({
        "$schema" => "https://www.speedscope.app/file-format-schema.json",
        "shared" => { "frames" => frame_list },
        "profiles" => profiles,
        "name" => "rbscope standalone capture",
        "exporter" => "rbscope v#{Rbscope::VERSION}"
      })
    end

    # Collapsed stack format for flamegraph.pl or inferno
    def to_collapsed
      @stacks.map { |stack, count| "#{stack} #{count}" }.join("\n")
    end

    private

    def capture_loop
      while @running
        sleep(@interval)
        next unless @running

        sample_all_threads
      end
    end

    def sample_all_threads
      Thread.list.each do |thread|
        next if thread == Thread.current # skip the capture thread
        next unless thread.alive?

        locs = thread.backtrace_locations(0, 128)
        next if locs.nil? || locs.empty?

        # Build stack key: leaf first (bottom of stack = leftmost in collapsed format)
        key = locs.reverse.map { |loc| "#{loc.path}:#{loc.lineno}:#{loc.label}" }.join(";")
        @stacks[key] += 1
        @sample_count += 1
      end
    end

    def parse_frame(raw)
      # "path:line:method"
      parts = raw.split(":", 3)
      if parts.size == 3
        [parts[0], parts[1].to_i, parts[2]]
      else
        [nil, nil, raw]
      end
    end
  end
end
