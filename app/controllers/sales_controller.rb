class SalesController < ApplicationController
  before_action :authenticate_user!

  def index
    @sales = Sale.includes(:item, :customer).order(created_at: :desc)
  end

  def new
    @items = Item.all
    @sale = Sale.new
    @customers = Customer.all
  end

  def create
    items = JSON.parse(params[:items])
    sale = current_user.sales.build(
      total_amount: calculate_total(items),
      is_debt: params[:is_debt],
      payment_method: params[:is_debt] ? 'debt' : 'cash'
    )

    if sale.save
      items.each do |item_data|
        item = Item.find(item_data["id"])
        sale.sales_items.create!(item: item, quantity: item_data["quantity"], price: item.price)
        item.update!(quantity: item.quantity - item_data["quantity"]) # Deduct stock
      end
      redirect_to pos_path, notice: "Sale completed!"
    else
      redirect_to pos_path, alert: "Error: #{sale.errors.full_messages.join(', ')}"
    end
  end

  private
  def calculate_total(items)
    items.sum { |item| item["price"] * item["quantity"] }
  end
end