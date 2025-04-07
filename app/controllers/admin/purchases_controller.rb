class Admin::PurchasesController < Admin::BaseController
  def index
    @purchases = Purchase.includes(:supplier).order(created_at: :desc)
  end

  def show
    @purchase = Purchase.find(params[:id])
    @purchase_items = @purchase.purchase_items.includes(:item)
  end
end