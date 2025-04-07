class CreateDebts < ActiveRecord::Migration[7.1]
  def change
    create_table :debts do |t|
      t.references :sale, null: false, foreign_key: true
      t.string :customer_name
      t.string :customer_number, null: false
      t.date :due_date
      t.decimal :remaining_amount

      t.timestamps
    end
  end
end
