# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# Example:
#
#   ["Action", "Comedy", "Drama", "Horror"].each do |genre_name|
#     MovieGenre.find_or_create_by!(name: genre_name)
#   end

# Seed Categories  
electronics = Category.create!(name: "Electronics")  
groceries = Category.create!(name: "Groceries")  

# Seed Suppliers  
supplier1 = Supplier.create!(  
  name: "Tech Supplier Inc",  
  contact: "00224466",  
  email: "john@techsupplier.com",  
  address: "123 Tech Street"  
)  

# Seed Items  
Item.create!(  
  name: "Wireless Mouse",  
  description: "Ergonomic wireless mouse",  
  sku: "WM-001",  
  quantity: 50,  
  low_stock_threshold: 10,  
  price: 25.99,  
  manufacturer: "TechCorp",  
  category: electronics  
)  

Item.create!(  
  name: "Organic Apples",  
  description: "Fresh organic apples",  
  sku: "OA-001",  
  quantity: 100,  
  low_stock_threshold: 20,  
  price: 2.99,  
  manufacturer: "FarmFresh",  
  category: groceries  
)  

# Seed a Purchase (Restock)  
purchase = Purchase.create!(  
  supplier: supplier1,  
  order_date: Date.today - 3.days,  
  received_date: Date.today,  
  total_cost: 500.00  
)  

PurchaseItem.create!(  
  purchase: purchase,  
  item: Item.find_by(name: "Wireless Mouse"),  
  quantity: 20,  
  unit_cost: 20.00  
)  