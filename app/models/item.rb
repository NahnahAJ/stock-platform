class Item < ApplicationRecord
  belongs_to :category
  has_many :purchase_items
  has_many :purchases, through: :purchase_items
  has_many :sales_items
  has_many :sales, through: :sales_items
  validates :quantity, numericality: {greater_than_or_equal_to: 0}
end
