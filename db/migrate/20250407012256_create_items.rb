class CreateItems < ActiveRecord::Migration[7.1]
  def change
    create_table :items do |t|
      t.string :name
      t.text :description
      t.string :sku
      t.integer :quantity, default: 0, null: false
      t.integer :low_stock_threshold, default: 10, null: false
      t.decimal :price, precision: 10, scale: 2, null: false
      t.string :manufacturer
      t.references :category, null: false, foreign_key: true

      t.timestamps
    end
  end
end
