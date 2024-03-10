# frozen_string_literal: true

class DocumentsController < ApplicationController
  before_action :set_document, only: %i[show update destroy]

  # GET /documents
  def index
    if params['user_id'].present?
      car_ids = Car.where(user_id: params['user_id']).map(&:id)
      maintenance_ids = Maintenance.where(car_id: car_ids).map(&:id)
      car_documents = Document.where(documentable_type: 'Car', documentable_id: car_ids)
      maintenance_documents = Document.where(documentable_type: 'Maintenance', documentable_id: maintenance_ids)
      all_documents = car_documents + maintenance_documents
      @documents = all_documents.map { |document| prep_raw_document(document) }
    else
      @documents = Document.all.map { |document| prep_raw_document(document) }
    end
    render json: @documents
  end

  # GET /documents/1
  def show
    render json: prep_raw_document(@document)
  end

  # POST /documents
  def create
    create_params = document_params
    create_params['attachment'] = params['attachment'].presence # if no image is chosen on new maintenance page, params['image'] comes in as a blank string, which throws a 500 error at Maintenance.new(create_params). This changes any params['image'] blank string to nil, which is fine in Maintenance.new(create_params).
    @document = Document.new(create_params)
    if @document.save
      render json: prep_raw_document(@document), status: :created, location: @document
    else
      render json: @document.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /documents/1
  def update
    if @document.update(document_params)
      render json: prep_raw_document(@document)
    else
      render json: @document.errors, status: :unprocessable_entity
    end
  end

  # DELETE /documents/1
  def destroy
    @document.destroy
  end

  private

  # Use callbacks to share common setup or constraints between actions.
  def set_document
    @document = Document.find(params[:id])
  end

  # Only allow a list of trusted parameters through.
  def document_params
    params.permit(:date, :name, :notes, :attachment, :documentable_id, :documentable_type)
  end
end
