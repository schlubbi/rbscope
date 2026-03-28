FROM ruby:3.3-slim

RUN apt-get update && apt-get install -y build-essential rustc cargo curl clang && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy gem source for path dependency
COPY gem/ /rbscope-gem/

# Pre-compile the native extension
RUN cd /rbscope-gem && bundle install && bundle exec rake compile

# Copy app source and install dependencies
COPY test-rails-app/ .
RUN sed -i 's|path: "../gem"|path: "/rbscope-gem"|' Gemfile
RUN bundle install --jobs 4

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s \
  CMD curl -sf http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:3000", "-t", "1:4"]
