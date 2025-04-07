# app/controllers/admin/suppliers_controller.rb
class Admin::SuppliersController < Admin::BaseController
  def index
    @suppliers = Supplier.all.order(:name)
  end

  def new
    @supplier = Supplier.new
  end

  def create
    @supplier = Supplier.new(supplier_params)
    if @supplier.save
      redirect_to admin_suppliers_path, notice: "Supplier created!"
    else
      render :new
    end
  end

  def edit
    @supplier = Supplier.find(params[:id])
  end

  def update
    @supplier = Supplier.find(params[:id])
    if @supplier.update(supplier_params)
      redirect_to admin_suppliers_path, notice: "Supplier updated!"
    else
      render :edit
    end
  end

  def destroy
    @supplier = Supplier.find(params[:id])
    @supplier.destroy
    redirect_to admin_suppliers_path, notice: "Supplier deleted!"
  end

  private

  def supplier_params
    params.require(:supplier).permit(:name, :contact, :email, :address)
  end
end