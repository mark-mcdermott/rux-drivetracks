# frozen_string_literal: true

require 'rails_helper'

RSpec.describe '/documents', type: :request do
  fixtures :users, :cars, :maintenances, :documents
  let(:valid_headers) { { Authorization: "Bearer #{@michael_token}" } }
  let(:valid_attributes) do
    {
      date: Date.parse('20200713'),
      name: 'name',
      notes: 'notes',
      documentable_type: 'Maintenance',
      documentable_id: maintenances(:fiat_alignment).id
    }
  end
  let(:invalid_attributes) do
    {
      date: Date.parse('20200713'),
      name: 'name',
      notes: 'notes',
      documentable_type: 'Maintenance',
      documentable_id: -1
    }
  end

  before :all do
    @michael_token = token_from_email_password('michaelscott@dundermifflin.com', 'password')
  end

  before do
    @fiat_title = documents(:fiat_title)
    @fiat_title.attachment.attach(fixture_file_upload(
                                    Rails.root.join('spec/fixtures/files/title-fiat-500.gif'), 'image/gif'
                                  ))
    @fiat_contract = documents(:fiat_contract)
    @fiat_contract.attachment.attach(fixture_file_upload(
                                       Rails.root.join('spec/fixtures/files/contract-fiat-500.webp'), 'image/webp'
                                     ))
    @civic_title = documents(:civic_title)
    @civic_title.attachment.attach(fixture_file_upload(
                                     Rails.root.join('spec/fixtures/files/title-honda-civic.png'), 'image/png'
                                   ))
    @civic_contract = documents(:civic_contract)
    @civic_contract.attachment.attach(fixture_file_upload(
                                        Rails.root.join('spec/fixtures/files/contract-honda-civic.png'), 'image/png'
                                      ))
    @elantra_title = documents(:elantra_title)
    @elantra_title.attachment.attach(fixture_file_upload(
                                       Rails.root.join('spec/fixtures/files/title-hyundai-elantra.pdf'), 'application/pdf'
                                     ))
    @elantra_contract = documents(:elantra_contract)
    @elantra_contract.attachment.attach(fixture_file_upload(
                                          Rails.root.join('spec/fixtures/files/contract-hyundai-elantra.jpg'), 'image/jpeg'
                                        ))
    @leaf_title = documents(:leaf_title)
    @leaf_title.attachment.attach(fixture_file_upload(
                                    Rails.root.join('spec/fixtures/files/title-nissan-leaf.png'), 'image/png'
                                  ))
    @leaf_contract = documents(:leaf_contract)
    @leaf_contract.attachment.attach(fixture_file_upload(
                                       Rails.root.join('spec/fixtures/files/contract-nissan-leaf.png'), 'image/png'
                                     ))
    @scion_title = documents(:scion_title)
    @scion_title.attachment.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/title-scion.jpg'),
                                                       'image/jpeg'))
    @scion_contract = documents(:scion_contract)
    @scion_contract.attachment.attach(fixture_file_upload(
                                        Rails.root.join('spec/fixtures/files/contract-scion.pdf'), 'application/pdf'
                                      ))
    @camry_title = documents(:camry_title)
    @camry_title.attachment.attach(fixture_file_upload(
                                     Rails.root.join('spec/fixtures/files/title-toyota-camry.jpg'), 'image/jpeg'
                                   ))
    @camry_contract = documents(:camry_contract)
    @camry_contract.attachment.attach(fixture_file_upload(
                                        Rails.root.join('spec/fixtures/files/contract-toyota-camry.jpg'), 'image/jpeg'
                                      ))
    @fiat_alignment_document_1 = documents(:fiat_alignment_document_1)
    @fiat_alignment_document_1.attachment.attach(fixture_file_upload(
                                                   Rails.root.join('spec/fixtures/files/fiat-alignment-1.png'), 'image/png'
                                                 ))
    @fiat_alignment_document_2 = documents(:fiat_alignment_document_2)
    @fiat_alignment_document_2.attachment.attach(fixture_file_upload(
                                                   Rails.root.join('spec/fixtures/files/fiat-alignment-2.txt'), 'text/plain'
                                                 ))
    @fiat_oil_change_document_1 = documents(:fiat_oil_change_document_1)
    @fiat_oil_change_document_1.attachment.attach(fixture_file_upload(
                                                    Rails.root.join('spec/fixtures/files/fiat-oil-change-1.txt'), 'text/plain'
                                                  ))
    @fiat_oil_change_document_2 = documents(:fiat_oil_change_document_2)
    @fiat_oil_change_document_2.attachment.attach(fixture_file_upload(
                                                    Rails.root.join('spec/fixtures/files/fiat-oil-change-2.txt'), 'text/plain'
                                                  ))
    @civic_brake_repair_document_1 = documents(:civic_brake_repair_document_1)
    @civic_brake_repair_document_1.attachment.attach(fixture_file_upload(
                                                       Rails.root.join('spec/fixtures/files/civic-brake-repair-1.jpg'), 'image/jpeg'
                                                     ))
    @civic_brake_repair_document_2 = documents(:civic_brake_repair_document_2)
    @civic_brake_repair_document_2.attachment.attach(fixture_file_upload(
                                                       Rails.root.join('spec/fixtures/files/civic-brake-repair-2.pdf'), 'application/pdf'
                                                     ))
    @civic_tire_rotation_document_1 = documents(:civic_tire_rotation_document_1)
    @civic_tire_rotation_document_1.attachment.attach(fixture_file_upload(
                                                        Rails.root.join('spec/fixtures/files/civic-tire-rotation-1.pdf'), 'application/pdf'
                                                      ))
    @civic_tire_rotation_document_2 = documents(:civic_tire_rotation_document_2)
    @civic_tire_rotation_document_2.attachment.attach(fixture_file_upload(
                                                        Rails.root.join('spec/fixtures/files/civic-tire-rotation-2.png'), 'image/png'
                                                      ))
    @elantra_new_tires_document_1 = documents(:elantra_new_tires_document_1)
    @elantra_new_tires_document_1.attachment.attach(fixture_file_upload(
                                                      Rails.root.join('spec/fixtures/files/elantra-new-tires-1.pdf'), 'application/pdf'
                                                    ))
    @elantra_new_tires_document_2 = documents(:elantra_new_tires_document_2)
    @elantra_new_tires_document_2.attachment.attach(fixture_file_upload(
                                                      Rails.root.join('spec/fixtures/files/elantra-new-tires-2.pdf'), 'application/pdf'
                                                    ))
    @elantra_repaired_body_document_1 = documents(:elantra_repaired_body_document_1)
    @elantra_repaired_body_document_1.attachment.attach(fixture_file_upload(
                                                          Rails.root.join('spec/fixtures/files/elantra-repaired-body-1.png'), 'image/png'
                                                        ))
    @elantra_repaired_body_document_2 = documents(:elantra_repaired_body_document_2)
    @elantra_repaired_body_document_2.attachment.attach(fixture_file_upload(
                                                          Rails.root.join('spec/fixtures/files/elantra-repaired-body-2.pdf'), 'application/pdf'
                                                        ))
    @leaf_windshield_replacement_document_1 = documents(:leaf_windshield_replacement_document_1)
    @leaf_windshield_replacement_document_1.attachment.attach(fixture_file_upload(
                                                                Rails.root.join('spec/fixtures/files/leaf-windshield-replacement-1.webp'), 'image/webp'
                                                              ))
    @leaf_windshield_replacement_document_2 = documents(:leaf_windshield_replacement_document_2)
    @leaf_windshield_replacement_document_2.attachment.attach(fixture_file_upload(
                                                                Rails.root.join('spec/fixtures/files/leaf-windshield-replacement-2.webp'), 'image/webp'
                                                              ))
    @leaf_new_spark_plugs_document_1 = documents(:leaf_new_spark_plugs_document_1)
    @leaf_new_spark_plugs_document_1.attachment.attach(fixture_file_upload(
                                                         Rails.root.join('spec/fixtures/files/leaf-new-spark-plugs-1.txt'), 'text/plain'
                                                       ))
    @leaf_new_spark_plugs_document_2 = documents(:leaf_new_spark_plugs_document_2)
    @leaf_new_spark_plugs_document_2.attachment.attach(fixture_file_upload(
                                                         Rails.root.join('spec/fixtures/files/leaf-new-spark-plugs-2.png'), 'image/png'
                                                       ))
    @scion_engine_overhaul_document_1 = documents(:scion_engine_overhaul_document_1)
    @scion_engine_overhaul_document_1.attachment.attach(fixture_file_upload(
                                                          Rails.root.join('spec/fixtures/files/scion-engine-overhaul-1.png'), 'image/png'
                                                        ))
    @scion_engine_overhaul_document_2 = documents(:scion_engine_overhaul_document_2)
    @scion_engine_overhaul_document_2.attachment.attach(fixture_file_upload(
                                                          Rails.root.join('spec/fixtures/files/scion-engine-overhaul-2.jpg'), 'image/jpeg'
                                                        ))
    @scion_5k_mile_maintenance_document_1 = documents(:scion_5k_mile_maintenance_document_1)
    @scion_5k_mile_maintenance_document_1.attachment.attach(fixture_file_upload(
                                                              Rails.root.join('spec/fixtures/files/scion-5k-mile-maintenance-1.jpg'), 'image/jpeg'
                                                            ))
    @scion_5k_mile_maintenance_document_2 = documents(:scion_5k_mile_maintenance_document_2)
    @scion_5k_mile_maintenance_document_2.attachment.attach(fixture_file_upload(
                                                              Rails.root.join('spec/fixtures/files/scion-5k-mile-maintenance-2.png'), 'image/png'
                                                            ))
    @camry_fuel_line_document_1 = documents(:camry_fuel_line_document_1)
    @camry_fuel_line_document_1.attachment.attach(fixture_file_upload(
                                                    Rails.root.join('spec/fixtures/files/camry-fuel-line-1.txt'), 'text/plain'
                                                  ))
    @camry_fuel_line_document_2 = documents(:camry_fuel_line_document_2)
    @camry_fuel_line_document_2.attachment.attach(fixture_file_upload(
                                                    Rails.root.join('spec/fixtures/files/camry-fuel-line-2.webp'), 'image/webp'
                                                  ))
    @camry_replaced_radiator_document_1 = documents(:camry_replaced_radiator_document_1)
    @camry_replaced_radiator_document_1.attachment.attach(fixture_file_upload(
                                                            Rails.root.join('spec/fixtures/files/camry-replaced-radiator-1.png'), 'image/png'
                                                          ))
    @camry_replaced_radiator_document_2 = documents(:camry_replaced_radiator_document_2)
    @camry_replaced_radiator_document_2.attachment.attach(fixture_file_upload(
                                                            Rails.root.join('spec/fixtures/files/camry-replaced-radiator-2.webp'), 'image/webp'
                                                          ))
  end

  describe 'GET /index' do
    it 'renders a successful response' do
      get documents_url, headers: valid_headers
      expect(response).to be_successful
    end

    it 'gets 36 documents' do
      get documents_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 36
    end

    it 'first document has correct properties' do
      get documents_url, headers: valid_headers
      documents = JSON.parse(response.body)
      fiat_title = documents.select { |document| document['name'] == 'Fiat title' }[0]
      michael = User.find_by(name: 'Michael Scott')
      fiat = Car.find_by(name: "Michael's Fiat 500")
      expect(fiat_title['date']).to be_nil
      expect(fiat_title['name']).to eq 'Fiat title'
      expect(fiat_title['notes']).to be_nil
      expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
      expect(fiat_title['carId']).to eq fiat.id
      expect(fiat_title['carName']).to eq fiat.name
      expect(fiat_title['userId']).to eq michael.id
      expect(fiat_title['userName']).to eq michael.name
    end

    it 'second document has correct properties' do
      get documents_url, headers: valid_headers
      documents = JSON.parse(response.body)
      elantra_tires = documents.select { |document| document['name'] == 'elantra_new_tires_document_1' }[0]
      jim = User.find_by(name: 'Jim Halpert')
      elantra = Car.find_by(name: "Jim's Hyundai Elantra")
      expect(elantra_tires['date']).to be_nil
      expect(elantra_tires['name']).to eq 'elantra_new_tires_document_1'
      expect(elantra_tires['notes']).to be_nil
      expect(elantra_tires['attachment']).to match(/http.*elantra-new-tires-1\.pdf/)
      expect(elantra_tires['carId']).to eq elantra.id
      expect(elantra_tires['carName']).to eq elantra.name
      expect(elantra_tires['userId']).to eq jim.id
      expect(elantra_tires['userName']).to eq jim.name
    end
  end

  describe 'GET /show' do
    it 'renders a successful response' do
      document = documents(:fiat_title)
      get document_url(document), headers: valid_headers
      expect(response).to be_successful
    end

    it 'document has correct properties' do
      document = documents(:fiat_title)
      fiat = cars(:fiat)
      michael = users(:michael)
      get document_url(document), headers: valid_headers
      fiat_title = JSON.parse(response.body)
      expect(fiat_title['date']).to be_nil
      expect(fiat_title['name']).to eq 'Fiat title'
      expect(fiat_title['notes']).to be_nil
      expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
      expect(fiat_title['carId']).to eq fiat.id
      expect(fiat_title['carName']).to eq fiat.name
      expect(fiat_title['userId']).to eq michael.id
      expect(fiat_title['userName']).to eq michael.name
    end
  end

  describe 'POST /create' do
    context 'with valid parameters' do
      it 'creates a new document' do
        expect do
          post documents_url, params: valid_attributes, headers: valid_headers, as: :json
        end.to change(Document, :count).by(1)
      end

      it 'renders a JSON response with the new document' do
        post documents_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end

    context 'with invalid parameters' do
      it 'does not create new document' do
        expect do
          post documents_url, params: invalid_attributes, headers: valid_headers, as: :json
        end.to change(Document, :count).by(0)
      end

      it 'renders a JSON response with errors for the new document' do
        post documents_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end
  end

  describe 'PATCH /update' do
    context 'with valid parameters' do
      let(:new_attributes) { { name: 'UpdatedName' } }

      it "updates document's description" do
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        document.reload
        expect(document.name).to eq('UpdatedName')
      end

      it 'renders a JSON response with the document' do
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including('application/json'))
      end

      it "document's other properties are still correct" do
        fiat = cars(:fiat)
        michael = users(:michael)
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        JSON.parse(response.body)
        fiat_title = JSON.parse(response.body)
        expect(fiat_title['date']).to be_nil
        expect(fiat_title['notes']).to be_nil
        expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
        expect(fiat_title['carId']).to eq fiat.id
        expect(fiat_title['carName']).to eq fiat.name
        expect(fiat_title['userId']).to eq michael.id
        expect(fiat_title['userName']).to eq michael.name
      end

      context 'with invalid parameters' do
        it 'renders a JSON response with errors for the document' do
          document = documents(:fiat_title)
          patch document_url(document), params: invalid_attributes, headers: valid_headers, as: :json
          expect(response).to have_http_status(:unprocessable_entity)
          expect(response.content_type).to match(a_string_including('application/json'))
        end
      end
    end

    describe 'DELETE /destroy' do
      it 'destroys the requested document' do
        document = Document.create! valid_attributes
        expect do
          delete document_url(document), headers: valid_headers, as: :json
        end.to change(Document, :count).by(-1)
      end
    end
  end
end
