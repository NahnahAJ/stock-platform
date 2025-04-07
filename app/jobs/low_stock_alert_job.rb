class LowStockAlertJob < ApplicationJob
  queue_as :default

  def perform(*args)
    # Do something later
    low_stock_items = Item.low_stock
    return if low_stock_items.empty?

    # Find all admin users
    User.where(admin: true).each do |admin|
      Notification.create!(
        user: admin,
        message: "Low stock alert: #{low_stock_items.pluck(:name).join(', ')}",
        read: false
      )
    end 
  end
end
