class Sale < ApplicationRecord
  belongs_to :user
  has_many :sales_items, dependent: :destroy  
  has_one :debt, dependent: :destroy  
  belongs_to :customer, optional: true

  accepts_nested_attributes_for :sales_items  

  after_create :create_debt_if_needed

  private
  def create_debt_if_needed
    return unless is_debt?
    Debt.create!(
      sale.self,
      customer.name: customer_name_param,
      due_date: 7.days.from_now,
      remaining_amount: total_amount

    )
  end
end
