# frozen_string_literal: true

class PostsController < ApplicationController
  before_action :set_post, only: [:show, :update, :destroy]

  # GET /posts
  def index
    @posts = Post.published.recent.includes(:comments).limit(20)
    render json: @posts.as_json(include: { comments: { only: [:id, :author, :body] } })
  end

  # GET /posts/heavy — CPU-heavy variant for profiling demos.
  # Runs multiple queries and does Ruby-side aggregation that shows up
  # clearly in flame graphs (PostsController, ActiveRecord, Trilogy).
  def heavy
    posts = Post.published.recent.includes(:comments).limit(20).to_a

    # Ruby-side aggregation work (hits safe points for rb_postponed_job)
    result = posts.map do |post|
      comments = post.comments.to_a
      word_counts = comments.map { |c| c.body.to_s.split(/\s+/).size }
      {
        id: post.id,
        title: post.title,
        author: post.author,
        comment_count: comments.size,
        total_words: word_counts.sum,
        avg_words: word_counts.empty? ? 0 : word_counts.sum.to_f / word_counts.size,
        longest_comment: comments.max_by { |c| c.body.to_s.length }&.body.to_s[0..100],
        tags: post.title.to_s.downcase.scan(/\w+/).uniq.sort,
      }
    end

    # Extra CPU: sort by multiple criteria
    result.sort_by! { |r| [-r[:total_words], -r[:comment_count], r[:title].to_s] }

    render json: { posts: result, meta: { count: result.size, generated_at: Time.now.iso8601 } }
  end

  # GET /posts/:id
  def show
    Post.where(id: @post.id).update_all("views_count = views_count + 1")
    render json: @post.as_json(include: :comments)
  end

  # POST /posts
  def create
    @post = Post.new(post_params)
    if @post.save
      render json: @post, status: :created
    else
      render json: { errors: @post.errors }, status: :unprocessable_entity
    end
  end

  # PATCH /posts/:id
  def update
    if @post.update(post_params)
      render json: @post
    else
      render json: { errors: @post.errors }, status: :unprocessable_entity
    end
  end

  # DELETE /posts/:id
  def destroy
    @post.destroy!
    head :no_content
  end

  private

  def set_post
    @post = Post.find(params[:id])
  end

  def post_params
    params.permit(:title, :body, :author, :published)
  end
end
