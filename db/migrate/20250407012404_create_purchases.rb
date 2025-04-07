class CreatePurchases < ActiveRecord::Migration[7.1]
  def change
    create_table :purchases do |t|
      t.references :supplier, null: false, foreign_key: true
      t.date :order_date, null: false
      t.date :received_date
      t.decimal :total_cost, precision: 10, scale: 2, default: 0.0

      t.timestamps
    end
  end
end
