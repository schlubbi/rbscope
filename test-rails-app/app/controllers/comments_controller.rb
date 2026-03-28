# frozen_string_literal: true

class CommentsController < ApplicationController
  before_action :set_post

  # GET /posts/:post_id/comments
  def index
    render json: @post.comments.order(created_at: :desc)
  end

  # POST /posts/:post_id/comments
  def create
    @comment = @post.comments.build(comment_params)
    if @comment.save
      render json: @comment, status: :created
    else
      render json: { errors: @comment.errors }, status: :unprocessable_entity
    end
  end

  # DELETE /posts/:post_id/comments/:id
  def destroy
    @post.comments.find(params[:id]).destroy!
    head :no_content
  end

  private

  def set_post
    @post = Post.find(params[:post_id])
  end

  def comment_params
    params.permit(:author, :body)
  end
end
