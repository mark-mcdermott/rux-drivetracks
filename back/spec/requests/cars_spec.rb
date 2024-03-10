require 'rails_helper'

RSpec.describe '/cars', type: :request do
  fixtures :users, :cars
  let(:valid_headers) { { Authorization: 'Bearer ' + @michael_token } }
  let(:valid_attributes) do
    {
      name: "Jim's Fiat 500",
      make: 'Fiat',
      model: '500',
      trim: 'Sport',
      color: 'Yellow',
      body: 'Hatchback',
      plate: '6XYK922',
      vin: '3C3CFFBR0CT382584',
      year: 2012,
      cost: 10_235.00,
      purchase_vendor: 'Ted Fleid',
      initial_mileage: 47_361,
      user_id: User.find_by(email: 'michaelscott@dundermifflin.com').id
    }
  end
  let(:invalid_attributes) do
    {
      name: '',
      make: 'Fiat',
      model: '500',
      trim: 'Sport',
      color: 'Yellow',
      body: 'Hatchback',
      plate: '6XYK922',
      vin: '3C3CFFBR0CT382584',
      year: 2012,
      cost: 10_235.00,
      purchase_vendor: 'Ted Fleid',
      initial_mileage: 47_361,
      user_id: User.find_by(email: 'michaelscott@dundermifflin.com').id
    }
  end

  before :all do
    @michael_token = token_from_email_password('michaelscott@dundermifflin.com', 'password')
    @ryan_token = token_from_email_password('ryanhoward@dundermifflin.com', 'password')
  end

  before do
    @fiat = cars(:fiat)
    @fiat.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/fiat-500.jpg'), 'image/jpeg'))
    @civic = cars(:civic)
    @civic.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/honda-civic.jpg'),
                                            'image/jpeg'))
    @elantra = cars(:elantra)
    @elantra.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/hyundai-elantra.jpg'),
                                              'image/jpeg'))
    @leaf = cars(:leaf)
    @leaf.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/nissan-leaf.jpg'),
                                           'image/jpeg'))
    @scion = cars(:scion)
    @scion.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/scion.jpg'), 'image/jpeg'))
    @camry = cars(:camry)
    @camry.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/toyota-camry.jpg'),
                                            'image/jpeg'))
  end

  describe 'GET /index' do
    it 'renders a successful response' do
      get cars_url, headers: valid_headers
      expect(response).to be_successful
    end

    it 'gets two cars a successful response' do
      get cars_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 6
    end

    it 'first car has correct properties' do
      get cars_url, headers: valid_headers
      cars = JSON.parse(response.body)
      fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
      expect(fiat['name']).to eq "Michael's Fiat 500"
      expect(fiat['userName']).to eq 'Michael Scott'
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
      expect(fiat['make']).to eq 'Fiat'
      expect(fiat['model']).to eq '500'
      expect(fiat['trim']).to eq 'Sport'
      expect(fiat['color']).to eq 'Yellow'
      expect(fiat['body']).to eq 'Hatchback'
      expect(fiat['plate']).to eq '6XYK922'
      expect(fiat['vin']).to eq '3C3CFFBR0CT382584'
      expect(fiat['year']).to eq 2012
      expect(fiat['cost']).to eq '10235.0'
      expect(fiat['purchase_vendor']).to eq 'Ted Fleid'
      expect(fiat['initial_mileage']).to eq 47_361
      expect(fiat['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
    end

    it 'second car has correct properties' do
      get cars_url, headers: valid_headers
      cars = JSON.parse(response.body)
      elantra = cars.find { |car| car['name'] == "Jim's Hyundai Elantra" }
      expect(elantra['name']).to eq "Jim's Hyundai Elantra"
      expect(elantra['userName']).to eq 'Jim Halpert'
      expect(elantra['image']).to be_kind_of(String)
      expect(elantra['image']).to match(/http.*hyundai-elantra\.jpg/)
      expect(elantra['make']).to eq 'Hyundai'
      expect(elantra['model']).to eq 'Elantra'
      expect(elantra['trim']).to eq 'GLS'
      expect(elantra['color']).to eq 'Black'
      expect(elantra['body']).to eq 'Sedan'
      expect(elantra['plate']).to eq '8CEU662'
      expect(elantra['vin']).to eq 'KMHDU46D17U090264'
      expect(elantra['year']).to eq 2007
      expect(elantra['cost']).to eq '15000.0'
      expect(elantra['purchase_vendor']).to eq 'Feit Hyundai'
      expect(elantra['initial_mileage']).to eq 53_032
      expect(elantra['userId']).to eq User.find_by(email: 'jimhalpert@dundermifflin.com').id
    end
  end

  describe 'GET /show' do
    it 'renders a successful response' do
      car = cars(:fiat)
      get car_url(car), headers: valid_headers
      expect(response).to be_successful
    end

    it 'gets correct car properties' do
      car = cars(:fiat)
      get car_url(car), headers: valid_headers
      fiat = JSON.parse(response.body)
      expect(fiat['name']).to eq "Michael's Fiat 500"
      expect(fiat['userName']).to eq 'Michael Scott'
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
      expect(fiat['make']).to eq 'Fiat'
      expect(fiat['model']).to eq '500'
      expect(fiat['trim']).to eq 'Sport'
      expect(fiat['color']).to eq 'Yellow'
      expect(fiat['body']).to eq 'Hatchback'
      expect(fiat['plate']).to eq '6XYK922'
      expect(fiat['vin']).to eq '3C3CFFBR0CT382584'
      expect(fiat['year']).to eq 2012
      expect(fiat['cost']).to eq '10235.0'
      expect(fiat['purchase_vendor']).to eq 'Ted Fleid'
      expect(fiat['initial_mileage']).to eq 47_361
      expect(fiat['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
    end
  end

  describe 'POST /create' do
    context 'with valid parameters' do
      it 'creates a new Car' do
        expect do
          post cars_url, params: valid_attributes, headers: valid_headers, as: :json
        end.to change(Car, :count).by(1)
      end

      it 'renders a JSON response with the new car' do
        post cars_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end

    context 'with invalid parameters' do
      it 'does not create a new Car' do
        expect do
          post cars_url, params: invalid_attributes, headers: valid_headers, as: :json
        end.to change(Car, :count).by(0)
      end

      it 'renders a JSON response with errors for the new car' do
        post cars_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end
  end

  describe 'PATCH /update' do
    context 'with valid parameters' do
      let(:new_attributes) { { name: 'UpdatedName' } }

      it "updates car's name" do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        car.reload
        expect(car.name).to eq('UpdatedName')
      end

      it 'renders a JSON response with the car' do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including('application/json'))
      end

      it "car's other properties are still correct" do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        fiat = JSON.parse(response.body)
        expect(fiat['userName']).to eq 'Michael Scott'
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['make']).to eq 'Fiat'
        expect(fiat['model']).to eq '500'
        expect(fiat['trim']).to eq 'Sport'
        expect(fiat['color']).to eq 'Yellow'
        expect(fiat['body']).to eq 'Hatchback'
        expect(fiat['plate']).to eq '6XYK922'
        expect(fiat['vin']).to eq '3C3CFFBR0CT382584'
        expect(fiat['year']).to eq 2012
        expect(fiat['cost']).to eq '10235.0'
        expect(fiat['purchase_vendor']).to eq 'Ted Fleid'
        expect(fiat['initial_mileage']).to eq 47_361
        expect(fiat['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
      end
    end

    context 'with invalid parameters' do
      it 'renders a JSON response with errors for the car' do
        car = cars(:fiat)
        patch car_url(car), params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including('application/json'))
      end
    end
  end

  describe 'DELETE /destroy' do
    it 'destroys the requested car' do
      car = Car.create! valid_attributes
      expect do
        delete car_url(car), headers: valid_headers, as: :json
      end.to change(Car, :count).by(-1)
    end
  end
end
