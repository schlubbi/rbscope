# frozen_string_literal: true

class CreatePosts < ActiveRecord::Migration[8.1]
  def change
    create_table :posts do |t|
      t.string :title, null: false
      t.text :body
      t.string :author, null: false
      t.integer :views_count, default: 0, null: false
      t.boolean :published, default: false, null: false
      t.timestamps
    end

    add_index :posts, :author
    add_index :posts, :published
    add_index :posts, :created_at
  end
end
