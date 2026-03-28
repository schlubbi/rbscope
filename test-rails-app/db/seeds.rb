# frozen_string_literal: true

# Seed the test database with sample data for profiling.

puts "Seeding database..."

authors = ["Alice", "Bob", "Charlie", "Diana", "Eve"]

20.times do |i|
  post = Post.create!(
    title: "Post #{i + 1}: #{["Performance Tuning", "Ruby Internals", "Rails Patterns", "Database Design", "System Architecture"].sample}",
    body: "Lorem ipsum dolor sit amet. " * (5 + rand(20)),
    author: authors.sample,
    published: i < 15, # first 15 are published
    created_at: rand(30).days.ago
  )

  rand(1..5).times do
    post.comments.create!(
      author: authors.sample,
      body: ["Great post!", "Thanks for sharing.", "I had a similar experience.", "Could you elaborate on this?", "Very insightful."].sample,
      created_at: post.created_at + rand(48).hours
    )
  end
end

puts "Created #{Post.count} posts with #{Comment.count} comments."
