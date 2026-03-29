# frozen_string_literal: true

Rails.application.routes.draw do
  # Profiling test endpoints
  get "health",    to: "test#health"
  get "fast",      to: "test#fast"
  get "slow",      to: "test#slow"
  get "allocate",  to: "test#allocate"
  get "work",      to: "test#work"
  get "rbscope_status", to: "test#rbscope_status"

  # CRUD resources — realistic Rails workload with DB queries
  resources :posts do
    resources :comments, only: [:index, :create, :destroy]
    collection do
      get :heavy
    end
  end

  # Profile control
  get "profile/start",   to: "profile#start"
  get "profile/stop",    to: "profile#stop"
  get "profile/status",  to: "profile#status"
  get "profile/capture", to: "profile#capture"
end
