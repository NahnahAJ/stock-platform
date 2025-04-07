class PurchasesController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin, except: [:index]

  def index
    @purchases = Purchase.includes(:supplier, :purchase_items).order(created_at: :desc)
  end

  def new
    @purchase = Purchase.new
    3.times { @purchase.purchase_items.build }
  end

  def create
    @purchase = Purchase.new(purchase_params)
    if @purchase.save
      redirect_to purchases_path, notice: "Purchase logged"
    else
      render :new
    end
  end

  private  
  def purchase_params  
    params.require(:purchase).permit(  
      :supplier_id, :order_date, :received_date,  
      purchase_items_attributes: [:item_id, :quantity, :unit_cost]  
    )  
  end  

  def require_admin  
    redirect_to root_path unless current_user.admin?  
  end  
end
