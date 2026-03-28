# frozen_string_literal: true

class CreateComments < ActiveRecord::Migration[8.1]
  def change
    create_table :comments do |t|
      t.references :post, null: false, foreign_key: true
      t.string :author, null: false
      t.text :body, null: false
      t.timestamps
    end

    add_index :comments, :author
  end
end
