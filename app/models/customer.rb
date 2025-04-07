class Customer < ApplicationRecord
    has_many :debts
    has_many :sales
end
