# frozen_string_literal: true

require 'rails_helper'
RSpec.describe '/maintenances', type: :request do
  fixtures :users
  fixtures :cars
  fixtures :maintenances
  let(:valid_headers) { { Authorization: "Bearer #{@michael_token}" } }
  let(:valid_attributes) do
    {
      date: Date.parse('20200713'),
      description: 'Alignment',
      vendor: 'Pep Boys',
      cost: 350.00,
      car_id: cars(:fiat).id
    }
  end
  let(:invalid_attributes) do
    {
      date: Date.parse('20200713'),
      description: nil,
      vendor: 'Pep Boys',
      cost: 350.00,
      car_id: cars(:fiat).id
    }
  end

  before :all do
    @michael_token = token_from_email_password('michaelscott@dundermifflin.com', 'password')
    @ryan_token = token_from_email_password('ryanhoward@dundermifflin.com', 'password')
  end

  before do
    @fiat_alignment = maintenances(:fiat_alignment)
    # @fiat_alignment.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-2.jpg'),'image/jpeg')])
    @fiat_oil_change = maintenances(:fiat_oil_change)
    # @fiat_oil_change.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-2.jpg'),'image/jpeg')])
    @civic_brake_repair = maintenances(:civic_brake_repair)
    # @civic_brake_repair.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-2.jpg'),'image/jpeg')])
    @civic_tire_rotation = maintenances(:civic_tire_rotation)
    # @civic_tire_rotation.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-2.jpg'),'image/jpeg')])
    @elantra_new_tires = maintenances(:elantra_new_tires)
    # @elantra_new_tires.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-2.jpg'),'image/jpeg')])
    @elantra_repaired_body = maintenances(:elantra_repaired_body)
    # @elantra_repaired_body.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-2.jpg'),'image/jpeg')])
    @leaf_windshield_replacement = maintenances(:leaf_windshield_replacement)
    # @leaf_windshield_replacement.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-2.jpg'),'image/jpeg')])
    @leaf_new_spark_plugs = maintenances(:leaf_new_spark_plugs)
    # @leaf_new_spark_plugs.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-2.jpg'),'image/jpeg')])
    @scion_engine_overhaul = maintenances(:scion_engine_overhaul)
    # @scion_engine_overhaul.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-2.jpg'),'image/jpeg')])
    @scion_5k_mile_maintenance = maintenances(:scion_5k_mile_maintenance)
    # @scion_5k_mile_maintenance.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-2.jpg'),'image/jpeg')])
    @camry_fuel_line = maintenances(:camry_fuel_line)
    # @camry_fuel_line.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-2.jpg'),'image/jpeg')])
    @camry_replaced_radiator = maintenances(:camry_replaced_radiator)
    # @camry_replaced_radiator.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-2.jpg'),'image/jpeg')])
  end

  describe 'GET /index' do
    it 'renders a successful response' do
      get maintenances_url, headers: valid_headers
      expect(response).to be_successful
    end

    it 'gets twenty maintenances' do
      get maintenances_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 12
    end

    it 'first maintenance has correct properties' do
      get maintenances_url, headers: valid_headers
      maintenances = JSON.parse(response.body)
      fiat = Car.find_by(name: "Michael's Fiat 500")
      michael = User.find_by(name: 'Michael Scott')
      alignment = maintenances.find do |maintenance|
        maintenance['car_id'] == fiat.id and maintenance['cost'] == '350.0'
      end
      expect(alignment['date']).to eq '2020-07-13'
      expect(alignment['description']).to eq 'Alignment'
      expect(alignment['vendor']).to eq 'Pep Boys'
      expect(alignment['cost']).to eq '350.0'
      expect(alignment['carId']).to eq fiat.id
      expect(alignment['carName']).to eq fiat.name
      expect(alignment['userId']).to eq michael.id
      expect(alignment['userName']).to eq michael.name
    end

    it 'second maintenance has correct properties' do
      get maintenances_url, headers: valid_headers
      maintenances = JSON.parse(response.body)
      elantra = Car.find_by(name: "Jim's Hyundai Elantra")
      jim = User.find_by(name: 'Jim Halpert')
      tires = maintenances.find { |maintenance| maintenance['car_id'] == elantra.id and maintenance['cost'] == '812.0' }
      expect(tires['date']).to eq '2020-01-11'
      expect(tires['description']).to eq 'New Tires'
      expect(tires['vendor']).to eq "Scott's"
      expect(tires['cost']).to eq '812.0'
      expect(tires['carId']).to eq elantra.id
      expect(tires['carName']).to eq elantra.name
      expect(tires['userId']).to eq jim.id
      expect(tires['userName']).to eq jim.name
    end
  end

  describe 'GET /show' do
    it 'renders a successful response' do
      maintenance = maintenances(:fiat_alignment)
      get maintenance_url(maintenance), headers: valid_headers
      expect(response).to be_successful
    end

    it 'gets correct maintenance properties' do
      maintenance = maintenances(:fiat_alignment)
      fiat = cars(:fiat)
      michael = users(:michael)
      get maintenance_url(maintenance.id), headers: valid_headers
      fiat_alignment = JSON.parse(response.body)
      expect(fiat_alignment['date']).to eq '2020-07-13'
      expect(fiat_alignment['description']).to eq 'Alignment'
      expect(fiat_alignment['vendor']).to eq 'Pep Boys'
      expect(fiat_alignment['cost']).to eq '350.0'
      expect(fiat_alignment['carId']).to eq fiat.id
      expect(fiat_alignment['carName']).to eq "Michael's Fiat 500"
      expect(fiat_alignment['userId']).to eq michael.id
      expect(fiat_alignment['userName']).to eq michael.name
    end
  end

  describe 'POST /create' do
    context 'with valid parameters' do
      it 'creates a new maintenance' do
        expect do
          post maintenances_url, params: valid_attributes, headers: valid_headers, as: :json
        end.to change(Maintenance, :count).by(1)
      end

      it 'renders a JSON response with the new maintenance' do
        post maintenances_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end

    context 'with invalid parameters' do
      it 'does not create new maintenance' do
        expect do
          post maintenances_url, params: invalid_attributes, headers: valid_headers, as: :json
        end.to change(Maintenance, :count).by(0)
      end

      it 'renders a JSON response with errors for the new car' do
        post maintenances_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end
  end

  describe 'PATCH /update' do
    context 'with valid parameters' do
      let(:new_attributes) { { description: 'UpdatedDescription' } }

      it "updates maintenance's description" do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        maintenance.reload
        expect(maintenance.description).to eq('UpdatedDescription')
      end

      it 'renders a JSON response with the maintenance' do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including('application/json'))
      end

      it "maintenance's other properties are still correct" do
        fiat = cars(:fiat)
        michael = users(:michael)
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        fiat_alignment = JSON.parse(response.body)
        expect(fiat_alignment['date']).to eq '2020-07-13'
        expect(fiat_alignment['vendor']).to eq 'Pep Boys'
        expect(fiat_alignment['cost']).to eq '350.0'
        expect(fiat_alignment['carId']).to eq fiat.id
        expect(fiat_alignment['carName']).to eq "Michael's Fiat 500"
        expect(fiat_alignment['userId']).to eq michael.id
        expect(fiat_alignment['userName']).to eq michael.name
      end
    end

    context 'with invalid parameters' do
      it 'renders a JSON response with errors for the maintenance' do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end
  end

  describe 'DELETE /destroy' do
    it 'destroys the requested maintenance' do
      maintenance = Maintenance.create! valid_attributes
      expect do
        delete maintenance_url(maintenance), headers: valid_headers, as: :json
      end.to change(Maintenance, :count).by(-1)
    end
  end
end
