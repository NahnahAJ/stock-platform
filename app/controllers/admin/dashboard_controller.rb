class Admin::DashboardController < Admin::BaseController  
  def index
    @low_stock_items = Item.low_stock.limit(5)  
    @recent_purchases = Purchase.includes(:supplier).order(created_at: :desc).limit(5)  
    @notifications = current_user.notifications.unread  
  end
end
