# frozen_string_literal: true

class PostsController < ApplicationController
  before_action :set_post, only: [:show, :update, :destroy]

  # GET /posts
  def index
    @posts = Post.published.recent.includes(:comments).limit(20)
    render json: @posts.as_json(include: { comments: { only: [:id, :author, :body] } })
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
