# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.1].define(version: 2025_04_07_100952) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "plpgsql"

  create_table "categories", force: :cascade do |t|
    t.string "name"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "customers", force: :cascade do |t|
    t.string "name"
    t.string "phone"
    t.string "email"
    t.text "address"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "debts", force: :cascade do |t|
    t.bigint "sale_id", null: false
    t.string "customer_name"
    t.string "customer_number", null: false
    t.date "due_date"
    t.decimal "remaining_amount"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.bigint "customer_id", null: false
    t.index ["customer_id"], name: "index_debts_on_customer_id"
    t.index ["sale_id"], name: "index_debts_on_sale_id"
  end

  create_table "items", force: :cascade do |t|
    t.string "name"
    t.text "description"
    t.string "sku"
    t.integer "quantity", default: 0, null: false
    t.integer "low_stock_threshold", default: 10, null: false
    t.decimal "price", precision: 10, scale: 2, null: false
    t.string "manufacturer"
    t.bigint "category_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["category_id"], name: "index_items_on_category_id"
  end

  create_table "notifications", force: :cascade do |t|
    t.text "message"
    t.boolean "read"
    t.bigint "user_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["user_id"], name: "index_notifications_on_user_id"
  end

  create_table "purchase_items", force: :cascade do |t|
    t.bigint "purchase_id", null: false
    t.bigint "item_id", null: false
    t.integer "quantity", null: false
    t.decimal "unit_cost", precision: 10, scale: 2, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["item_id"], name: "index_purchase_items_on_item_id"
    t.index ["purchase_id", "item_id"], name: "index_purchase_items_on_purchase_id_and_item_id", unique: true
    t.index ["purchase_id"], name: "index_purchase_items_on_purchase_id"
  end

  create_table "purchases", force: :cascade do |t|
    t.bigint "supplier_id", null: false
    t.date "order_date", null: false
    t.date "received_date"
    t.decimal "total_cost", precision: 10, scale: 2, default: "0.0"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["supplier_id"], name: "index_purchases_on_supplier_id"
  end

  create_table "sale_items", force: :cascade do |t|
    t.bigint "sale_id", null: false
    t.bigint "item_id", null: false
    t.integer "quantity"
    t.decimal "price"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["item_id"], name: "index_sale_items_on_item_id"
    t.index ["sale_id"], name: "index_sale_items_on_sale_id"
  end

  create_table "sales", force: :cascade do |t|
    t.bigint "user_id", null: false
    t.datetime "sale_date"
    t.decimal "total_amount", precision: 10, scale: 2, null: false
    t.string "payment_method"
    t.boolean "is_debt", default: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.bigint "customer_id", null: false
    t.index ["customer_id"], name: "index_sales_on_customer_id"
    t.index ["user_id"], name: "index_sales_on_user_id"
  end

  create_table "suppliers", force: :cascade do |t|
    t.string "name"
    t.string "contact"
    t.string "email"
    t.text "address"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.boolean "admin", default: false
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
  end

  add_foreign_key "debts", "customers"
  add_foreign_key "debts", "sales"
  add_foreign_key "items", "categories"
  add_foreign_key "notifications", "users"
  add_foreign_key "purchase_items", "items"
  add_foreign_key "purchase_items", "purchases"
  add_foreign_key "purchases", "suppliers"
  add_foreign_key "sale_items", "items"
  add_foreign_key "sale_items", "sales"
  add_foreign_key "sales", "customers"
  add_foreign_key "sales", "users"
end
