class Purchase < ApplicationRecord
  belongs_to :supplier
  has_many :purchase_items, dependent: :destroy  
  accepts_nested_attributes_for :purchase_items  
end
