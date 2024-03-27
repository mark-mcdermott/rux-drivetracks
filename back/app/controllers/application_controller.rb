# frozen_string_literal: true

class ApplicationController < ActionController::API
  SECRET_KEY_BASE = Rails.application.secret_key_base
  before_action :require_login
  rescue_from StandardError, with: :response_internal_server_error

  def require_login
    response_unauthorized if current_user_raw.blank?
  end

  # this is safe to send to the frontend, excludes password_digest, created_at, updated_at
  def user_from_token
    user = prep_raw_user(current_user_raw)
    render json: { data: user, status: 200 }
  end

  # unsafe/internal: includes password_digest, created_at, updated_at - we don't want those going to the frontend
  def current_user_raw
    return if decoded_token.blank?

    user_id = decoded_token[0]['user_id']
    @user = User.find_by(id: user_id)
  end

  def encode_token(payload)
    JWT.encode payload, SECRET_KEY_BASE, 'HS256'
  end

  def decoded_token
    return unless auth_header && (auth_header.split(' ')[0] == 'Bearer')

    token = auth_header.split(' ')[1]
    begin
      JWT.decode token, SECRET_KEY_BASE, true, { algorithm: 'HS256' }
    rescue JWT::DecodeError
      []
    end
  end

  def response_unauthorized
    render status: :unauthorized, json: { status: 401, message: 'Unauthorized' }
  end

  def response_internal_server_error
    render status: :internal_server_error, json: { status: 500, message: 'Internal Server Error' }
  end

  # We don't want to send the whole user record from the database to the frontend, so we only send what we need.
  # The db user row has password_digest (unsafe) and created_at and updated_at (extraneous).
  # We also change avatar from a weird active_storage object to just the avatar url before it gets to the frontend.
  def prep_raw_user(user)
    avatar = user.avatar.present? ? url_for(user.avatar) : nil
    car_ids = Car.where(user_id: user.id).map(&:id)
    cars = Car.where(user_id: user.id).map { |car| prep_raw_car(car) }
    maintenances_ids = Maintenance.where(car_id: car_ids).map(&:id)
    maintenances = Maintenance.where(car_id: car_ids).map { |maintenance| prep_raw_maintenance(maintenance) }
    documents_ids = Document.where(documentable_id: car_ids, documentable_type: "Car").or(Document.where(documentable_id: maintenances_ids, documentable_type: "Maintenance")).map { |document| document.id }
    documents = Document.where(documentable_id: car_ids, documentable_type: "Car").or(Document.where(documentable_id: maintenances_ids, documentable_type: "Maintenance")).map { |document| prep_raw_document(document) }
      
    user = user.admin ? user.slice(:id, :email, :name, :admin) : user.slice(:id, :email, :name)
    user['avatar'] = avatar
    user['car_ids'] = car_ids
    user['cars'] = cars
    user['maintenances_ids'] = maintenances_ids
    user['maintenances'] = maintenances
    user['documents_ids'] = documents_ids
    user['documents'] = documents
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    maintenances = Maintenance.where(car_id: car.id).map { |maintenance| prep_raw_maintenance(maintenance) }
    # documents_ids = Document.where(documentable_id: car_ids, documentable_type: "Car").map { |document| document.id }
    documents = Document.where(documentable_id: car.id, documentable_type: 'Car').map do |document|
      prep_raw_document(document)
    end
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id, :name, :year, :make, :model, :trim, :body, :color, :plate, :vin, :cost, :initial_mileage, :purchase_date,
                    :purchase_vendor)
    car['cost'] = number_to_currency(car['cost'])
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    car['maintenances'] = maintenances
    car['documents'] = documents
    car
  end

  def prep_raw_maintenance(maintenance)
    car = Car.find(maintenance.car_id)
    user = User.find(car.user_id)
    # images = maintenance.images.present? ? maintenance.images.map { |image| url_for(image) } : nil
    documents = Document.where(documentable_id: maintenance.id, documentable_type: 'Maintenance').map do |document|
      prep_raw_document(document)
    end
    maintenance = maintenance.slice(:id, :date, :description, :vendor, :cost, :car_id)
    maintenance['cost'] = number_to_currency(maintenance['cost'])
    maintenance['carId'] = car.id
    maintenance['carName'] = car.name
    maintenance['userId'] = user.id
    maintenance['userName'] = user.name
    maintenance['documents'] = documents
    # maintenance['images'] = images
    maintenance
  end

  def prep_raw_document(document)
    attachment_path = document.attachment.present? ? url_for(document.attachment) : nil
    attachment_file = attachment_path.present? ? File.basename(attachment_path) : nil
    documentable_type = document.documentable_type
    documentable_id = document.documentable_id
    document = document.slice(:id, :date, :name, :notes)
    document['attachment'] = attachment_path
    document['attachmentFile'] = attachment_file
    car_id = nil
    if documentable_type == 'Car'
      car_id = documentable_id
    elsif documentable_type == 'Maintenance'
      maintenance_id = documentable_id
      maintenance = Maintenance.find(maintenance_id)
      car_id = maintenance.car_id
      document['maintenanceId'] = maintenance_id
      document['maintenanceDate'] = maintenance.date
      document['maintenanceDescription'] = maintenance.description
    end
    car = Car.find(car_id)
    user = User.find(car.user_id)
    document['carId'] = car_id
    document['carName'] = car.name
    document['userId'] = user.id
    document['userName'] = user.name
    document
  end

  def number_to_currency(amount)
    ActionController::Base.helpers.number_to_currency(amount)
  end

  def currency_to_number(currency)
    currency.to_s.gsub(/[$,]/,'').to_f
  end

  private

  def auth_header
    request.headers['Authorization']
  end
end
