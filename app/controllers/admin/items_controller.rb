# app/controllers/admin/items_controller.rb  
class Admin::ItemsController < Admin::BaseController  
  def index  
    @items = Item.includes(:category).order(:name)  
    if params[:search].present?  
      @items = @items.where("name ILIKE ?", "%#{params[:search]}%")  
    end  
  end  

  def edit  
    @item = Item.find(params[:id])  
  end  

  def update  
    @item = Item.find(params[:id])  
    if @item.update(item_params)  
      redirect_to admin_items_path, notice: "Item updated!"  
    else  
      render :edit  
    end  
  end  

  def destroy  
    @item = Item.find(params[:id])  
    @item.destroy  
    redirect_to admin_items_path, notice: "Item deleted!"  
  end  

  private  

  def item_params  
    params.require(:item).permit(:name, :quantity, :low_stock_threshold, :price)  
  end  
end  