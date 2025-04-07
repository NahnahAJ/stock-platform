class AddCustomerToSales < ActiveRecord::Migration[7.1]
  def change
    add_reference :sales, :customer, null: false, foreign_key: true
  end
end
