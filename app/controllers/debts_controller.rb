class DebtsController < ApplicationController
  def index
    @debts = Debt.includes(:customer, :sale).all
  end
end
