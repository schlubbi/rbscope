FROM ruby:3.3-slim

RUN apt-get update && apt-get install -y build-essential rustc cargo && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy gem first for layer caching
COPY gem/ /rbscope-gem/
COPY test-rails-app/Gemfile test-rails-app/Gemfile.lock* ./

RUN bundle install --jobs 4

COPY test-rails-app/ .

EXPOSE 3000
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:3000", "-t", "1:4"]
