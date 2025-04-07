class PurchaseItem < ApplicationRecord
  belongs_to :purchase
  belongs_to :item

  after_create :update_item_quantity  

  private  
  def update_item_quantity  
    item.update!(quantity: item.quantity + quantity)  
  end  
end
