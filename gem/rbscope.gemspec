# frozen_string_literal: true

require_relative "lib/rbscope/version"

Gem::Specification.new do |spec|
  spec.name = "rbscope"
  spec.version = Rbscope::VERSION
  spec.authors = ["Stefan Jöst"]
  spec.email = ["mail@schlubbi.io"]

  spec.summary = "Ruby X-ray: always-on profiler with USDT probes and eBPF collection"
  spec.description = <<~DESC
    rbscope is a modern Ruby profiler that emits USDT probes for external
    eBPF-based collection. Successor to tracecap by Theo Julienne.
    Designed for always-on profiling with minimal in-process overhead.
  DESC
  spec.homepage = "https://github.com/schlubbi/rbscope"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{rs,toml,rb,lock}",
    "LICENSE.txt",
    "README.md"
  ]

  spec.require_paths = ["lib"]
  spec.extensions = ["ext/rbscope/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rb_sys", "~> 0.9"
  spec.add_development_dependency "minitest", "~> 5.0"
end
