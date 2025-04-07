class AddCustomIndexToPurchaseItems < ActiveRecord::Migration[7.1]
  def change
    add_index :purchase_items, [:purchase_id, :item_id], unique: true 
  end
end
