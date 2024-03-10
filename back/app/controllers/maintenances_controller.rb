# frozen_string_literal: true

class MaintenancesController < ApplicationController
  before_action :set_maintenance, only: %i[show update destroy]

  # GET /maintenances
  def index
    @maintenances = if params['user_id'].present?
                      Maintenance.joins(car: [:user]).where(users: { id: params['user_id'] }).map do |maintenance|
                        prep_raw_maintenance(maintenance)
                      end
                    else
                      Maintenance.all.map { |maintenance| prep_raw_maintenance(maintenance) }
                    end
    render json: @maintenances
  end

  # GET /maintenances/1
  def show
    render json: prep_raw_maintenance(@maintenance)
  end

  # POST /maintenances
  def create
    create_params = maintenance_params
    # create_params['images'] = params['images'].blank? ? nil : params['images'] # if no image is chosen on new maintenance page, params['image'] comes in as a blank string, which throws a 500 error at Maintenance.new(create_params). This changes any params['image'] blank string to nil, which is fine in Maintenance.new(create_params).
    create_params['car_id'] = create_params['car_id'].to_i
    @maintenance = Maintenance.new(create_params)
    if @maintenance.save
      prepped_maintenance = prep_raw_maintenance(@maintenance)
      render json: prepped_maintenance, status: :created, location: @maintenance
    else
      render json: @maintenance.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /maintenances/1
  def update
    if @maintenance.update(maintenance_params)
      render json: prep_raw_maintenance(@maintenance)
    else
      render json: @maintenance.errors, status: :unprocessable_entity
    end
  end

  # DELETE /maintenances/1
  def destroy
    @maintenance.destroy
  end

  private

  # Use callbacks to share common setup or constraints between actions.
  def set_maintenance
    @maintenance = Maintenance.find(params[:id])
  end

    # Only allow a list of trusted parameters through.
    def maintenance_params
      # params.permit(:id, :date, :description, :vendor, :cost, :images, :car_id)
      params.permit(:id, :date, :description, :vendor, :cost, :car_id)
    end
end
