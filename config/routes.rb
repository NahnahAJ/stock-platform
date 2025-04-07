Rails.application.routes.draw do
  resources :customers
  resources :debts, only: [:index]
  resources :sales, only: [:index, :new, :create]

  namespace :admin do

    root to: "dashboard#index"   
    resources :items, :suppliers, :purchases, :notifications 
  end
  devise_for :users
  resources :purchases, only: [:index, :new, :create]  
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
