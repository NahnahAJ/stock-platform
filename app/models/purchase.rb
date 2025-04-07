class Purchase < ApplicationRecord
  belongs_to :supplier
  has_many :purchase_items, dependent: :destroy  
  accepts_nested_attributes_for :purchase_items  
  before_save :calculate_total_cost

  private  
  def calculate_total_cost  
    self.total_cost = purchase_items.sum { |pi| pi.quantity * pi.unit_cost }  
  end 
end
