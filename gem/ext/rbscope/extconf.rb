require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("rbscope/rbscope") do |r|
  r.profile = ENV.fetch("RBSCOPE_PROFILE", :release).to_sym
  r.extra_rustflags = ENV.fetch("RBSCOPE_RUSTFLAGS", "").split
end
