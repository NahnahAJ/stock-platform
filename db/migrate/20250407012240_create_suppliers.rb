class CreateSuppliers < ActiveRecord::Migration[7.1]
  def change
    create_table :suppliers do |t|
      t.string :name
      t.string :contact
      t.string :email
      t.text :address

      t.timestamps
    end
  end
end
