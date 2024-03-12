# frozen_string_literal: true

Rails.application.routes.draw do
  mount Rswag::Ui::Engine => '/api-docs'
  mount Rswag::Api::Engine => '/api-docs'
  resources :documents
  resources :users
  resources :cars
  resources :maintenances
  get 'health', to: 'health#index'
  post 'login', to: 'authentications#create'
  get 'me', to: 'application#user_from_token'
end
