# frozen_string_literal: true

class Comment < ApplicationRecord
  belongs_to :post, counter_cache: false

  validates :author, presence: true
  validates :body, presence: true
end
