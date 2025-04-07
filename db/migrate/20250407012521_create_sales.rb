class CreateSales < ActiveRecord::Migration[7.1]
  def change
    create_table :sales do |t|
      t.references :user, null: false, foreign_key: true
      t.datetime :sale_date
      t.decimal :total_amount, precision: 10, scale: 2, null: false  
      t.string :payment_method
      t.boolean :is_debt, default: false

      t.timestamps
    end
  end
end
