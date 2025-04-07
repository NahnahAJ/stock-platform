class Debt < ApplicationRecord
  belongs_to :sale
  belongs_to :customer

  validates :remaining_amount, numericality: { greater_than_or_equal_to: 0 }  
end
