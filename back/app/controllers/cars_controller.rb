# frozen_string_literal: true

class CarsController < ApplicationController
  before_action :set_car, only: %i[update destroy]

  # GET /cars
  def index
    @cars = if params['user_id'].present?
              Car.where(user_id: params['user_id']).map { |car| prep_raw_car(car) }
            else
              Car.all.map { |car| prep_raw_car(car) }
            end
    render json: @cars
  end

  # GET /cars/1
  def show
    car = Car.finds(params[:id])
    render json: prep_raw_car(car)

  rescue ActiveRecord::RecordNotFound => e
    render status: :not_found, json: { errors: e.message }
  end

  # POST /cars
  def create
    create_params = car_params
    create_params['image'] = params['image'].presence # if no image is chosen on new car page, params['image'] comes in as a blank string, which throws a 500 error at User.new(user_params). This changes any params['avatar'] blank string to nil, which is fine in User.new(user_params).
    @car = Car.new(create_params)
    if @car.save
      render json: prep_raw_car(@car), status: :created, location: @car
    else
      render json: @car.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /cars/1
  def update
    if @car.update(car_params)
      render json: prep_raw_car(@car)
    else
      render json: @car.errors, status: :unprocessable_entity
    end
  end

  # DELETE /cars/1
  def destroy
    @car.destroy
  end

  private

  # Use callbacks to share common setup or constraints between actions.
  def set_car
    @car = Car.find(params[:id])
  end

  # Only allow a list of trusted parameters through.
  def car_params
    params.permit(:id, :name, :image, :year, :make, :model, :trim, :body, :color, :plate, :vin, :cost,
                  :initial_mileage, :purchase_date, :purchase_vendor, :user_id)
  end
end
