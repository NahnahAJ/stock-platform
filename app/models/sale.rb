class Sale < ApplicationRecord
  belongs_to :user
  has_many :sales_items, dependent: :destroy  
  has_one :debt, dependent: :destroy  
  accepts_nested_attributes_for :sales_items  
end
