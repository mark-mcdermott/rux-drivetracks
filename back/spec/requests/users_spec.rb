# frozen_string_literal: true

require 'rails_helper'
require 'spec_helper'

RSpec.describe '/users', type: :request do
  fixtures :users, :cars
  let(:valid_headers) { { Authorization: "Bearer #{@michael_token}" } }
  let(:admin_2_headers) { { Authorization: "Bearer #{@ryan_token}" } }
  let(:invalid_token_header) { { Authorization: 'Bearer xyz' } }
  let(:poorly_formed_header) { { Authorization: "Bear #{@michael_token}" } }
  let(:user_valid_create_params_mock_1) do
    { name: 'First1 Last1', email: 'one@mail.com', admin: 'false', password: 'password',
      avatar: fixture_file_upload('spec/fixtures/files/michael-scott.png', 'image/png') }
  end
  let(:user_invalid_create_params_email_poorly_formed_mock_1) do
    { name: '', email: 'not_an_email', admin: 'false', password: 'password',
      avatar: fixture_file_upload('spec/fixtures/files/michael-scott.png', 'image/png') }
  end
  let(:valid_user_update_attributes) { { name: 'UpdatedName' } }
  let(:invalid_user_update_attributes) { { email: 'not_an_email' } }

  before :all do
    @michael_token = token_from_email_password('michaelscott@dundermifflin.com', 'password')
    @ryan_token = token_from_email_password('ryanhoward@dundermifflin.com', 'password')
  end

  before do
    @user1 = users(:michael)
    avatar1 = fixture_file_upload(Rails.root.join('spec/fixtures/files/michael-scott.png'), 'image/png')
    @user1.avatar.attach(avatar1)
    @user2 = users(:jim)
    avatar2 = fixture_file_upload(Rails.root.join('spec/fixtures/files/jim-halpert.png'), 'image/png')
    @user2.avatar.attach(avatar2)
    cars(:fiat).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/fiat-500.jpg'),
                                                 'image/jpeg'))
    cars(:civic).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/honda-civic.jpg'),
                                                  'image/jpeg'))
    cars(:elantra).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/hyundai-elantra.jpg'),
                                                    'image/jpeg'))
    cars(:leaf).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/nissan-leaf.jpg'),
                                                 'image/jpeg'))
    cars(:scion).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/scion.jpg'),
                                                  'image/jpeg'))
    cars(:camry).image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/toyota-camry.jpg'),
                                                  'image/jpeg'))
  end

  describe 'GET /index' do
    context 'with valid headers' do
      it 'renders a successful response' do
        get users_url, headers: valid_headers
        expect(response).to be_successful
      end

      it 'gets four users' do
        get users_url, headers: valid_headers
        expect(JSON.parse(response.body).length).to eq 4
      end

      it "gets first users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        michael = users.find { |user| user['email'] == 'michaelscott@dundermifflin.com' }
        michael['car_ids']
        cars = michael['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(michael['name']).to eq 'Michael Scott'
        expect(michael['email']).to eq 'michaelscott@dundermifflin.com'
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['userName']).to eq 'Michael Scott'
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
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
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['userName']).to eq 'Michael Scott'
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq 'Honda'
        expect(civic['model']).to eq 'Civic'
        expect(civic['trim']).to eq 'Vp'
        expect(civic['color']).to eq 'Blue'
        expect(civic['body']).to eq 'Sedan'
        expect(civic['plate']).to eq '4HGJ708'
        expect(civic['vin']).to eq '2HGEJ6618XH589506'
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq '10352.0'
        expect(civic['purchase_vendor']).to eq 'Howdy Honda'
        expect(civic['initial_mileage']).to eq 78_032
        expect(civic['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
      end

      it "gets second users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        jim = users.find { |user| user['email'] == 'jimhalpert@dundermifflin.com' }
        jim['car_ids']
        cars = jim['cars']
        elantra = cars.find { |car| car['name'] == "Jim's Hyundai Elantra" }
        leaf = cars.find { |car| car['name'] == "Jim's Nissan Leaf" }
        expect(jim['name']).to eq 'Jim Halpert'
        expect(jim['email']).to eq 'jimhalpert@dundermifflin.com'
        expect(jim['admin']).to be_nil or eq false
        expect(jim['avatar']).to be_kind_of(String)
        expect(jim['avatar']).to match(/http.*\jim-halpert\.png/)
        expect(jim['password']).to be_nil
        expect(jim['password_digest']).to be_nil
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
        expect(leaf['name']).to eq "Jim's Nissan Leaf"
        expect(leaf['userName']).to eq 'Jim Halpert'
        expect(leaf['image']).to be_kind_of(String)
        expect(leaf['image']).to match(/http.*nissan-leaf\.jpg/)
        expect(leaf['make']).to eq 'Nissan'
        expect(leaf['model']).to eq 'Leaf'
        expect(leaf['trim']).to eq 'SV'
        expect(leaf['color']).to eq 'Silver'
        expect(leaf['body']).to eq 'Hatchback'
        expect(leaf['plate']).to eq 'ABC123'
        expect(leaf['vin']).to eq '1N4AZ1CP8LC310110'
        expect(leaf['year']).to eq 2020
        expect(leaf['cost']).to eq '22590.0'
        expect(leaf['purchase_vendor']).to eq 'Carvana'
        expect(leaf['initial_mileage']).to eq 21_440
        expect(leaf['userId']).to eq User.find_by(email: 'jimhalpert@dundermifflin.com').id
      end
    end

    context 'with invalid headers' do
      it 'renders an unsuccessful response' do
        get users_url, headers: invalid_token_header
        expect(response).not_to be_successful
      end
    end
  end

  describe 'GET /show' do
    context 'with valid headers' do
      it 'renders a successful response' do
        get user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end

      it "gets users' correct details" do
        get user_url(@user1), headers: valid_headers
        michael = JSON.parse(response.body)
        michael['car_ids']
        cars = michael['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(michael['name']).to eq 'Michael Scott'
        expect(michael['email']).to eq 'michaelscott@dundermifflin.com'
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['userName']).to eq 'Michael Scott'
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
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
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['userName']).to eq 'Michael Scott'
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq 'Honda'
        expect(civic['model']).to eq 'Civic'
        expect(civic['trim']).to eq 'Vp'
        expect(civic['color']).to eq 'Blue'
        expect(civic['body']).to eq 'Sedan'
        expect(civic['plate']).to eq '4HGJ708'
        expect(civic['vin']).to eq '2HGEJ6618XH589506'
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq '10352.0'
        expect(civic['purchase_vendor']).to eq 'Howdy Honda'
        expect(civic['initial_mileage']).to eq 78_032
        expect(civic['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
      end
    end

    context 'with invalid headers' do
      it 'renders an unsuccessful response' do
        get user_url(@user1), headers: invalid_token_header
        expect(response).not_to be_successful
      end
    end
  end

  describe 'POST /users' do
    context 'with valid parameters' do
      it 'creates a new User' do
        expect do
          post users_url, params: user_valid_create_params_mock_1
        end.to change(User, :count).by(1)
      end

      it 'renders a successful response' do
        post users_url, params: user_valid_create_params_mock_1
        expect(response).to be_successful
      end

      it 'sets correct user details' do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user['name']).to eq 'First1 Last1'
        expect(user['email']).to eq 'one@mail.com'
        expect(user['admin']).to eq(false).or(be_nil)
        expect(user['avatar']).to be_nil
        expect(user['password']).to be_nil
        expect(user['password_digest']).to be_kind_of(String)
      end

      it 'attaches user avatar' do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user.avatar.attached?).to eq(true)
        expect(url_for(user.avatar)).to be_kind_of(String)
        expect(url_for(user.avatar)).to match(/http.*michael-scott\.png/)
      end
    end

    context 'with invalid parameters (email poorly formed)' do
      it 'does not create a new User' do
        expect do
          post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        end.to change(User, :count).by(0)
      end

      it 'renders a 422 response' do
        post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end
  end

  describe 'PATCH /update' do
    context 'with valid parameters and headers' do
      it "updates user's name" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(@user1.name).to eq('UpdatedName')
      end

      it "updates user's name in their cars" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        get user_url(@user1), headers: valid_headers
        user = JSON.parse(response.body)
        user['car_ids']
        cars = user['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(fiat['userName']).to eq 'UpdatedName'
        expect(civic['userName']).to eq 'UpdatedName'
      end

      it "doesn't change the other user attributes" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        get user_url(@user1), headers: valid_headers
        user = JSON.parse(response.body)
        user['car_ids']
        cars = user['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(@user1['email']).to eq 'michaelscott@dundermifflin.com'
        expect(@user1['admin']).to eq true
        expect(@user1['avatar']).to be_nil
        expect(@user1['password']).to be_nil
        expect(@user1['password_digest']).to be_kind_of(String)
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(url_for(fiat['image'])).to be_kind_of(String)
        expect(url_for(fiat['image'])).to match(/http.*fiat-500\.jpg/)
        expect(fiat['name']).to eq "Michael's Fiat 500"
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
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(url_for(civic['image'])).to be_kind_of(String)
        expect(url_for(civic['image'])).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq 'Honda'
        expect(civic['model']).to eq 'Civic'
        expect(civic['trim']).to eq 'Vp'
        expect(civic['color']).to eq 'Blue'
        expect(civic['body']).to eq 'Sedan'
        expect(civic['plate']).to eq '4HGJ708'
        expect(civic['vin']).to eq '2HGEJ6618XH589506'
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq '10352.0'
        expect(civic['purchase_vendor']).to eq 'Howdy Honda'
        expect(civic['initial_mileage']).to eq 78_032
        expect(civic['userId']).to eq User.find_by(email: 'michaelscott@dundermifflin.com').id
      end

      it 'is successful' do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(response).to be_successful
      end
    end

    context 'with invalid parameters but valid headers' do
      it 'renders a 422 response' do
        patch user_url(@user1), params: invalid_user_update_attributes, headers: valid_headers
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end

    context 'with valid parameters but invalid headers' do
      it 'renders a 401 response' do
        patch user_url(@user1), params: valid_user_update_attributes, headers: invalid_token_header
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'DELETE /destroy' do
    context 'with valid headers' do
      it 'destroys the requested user' do
        expect do
          delete user_url(@user1), headers: valid_headers
        end.to change(User, :count).by(-1)
      end

      it 'renders a successful response' do
        delete user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end
    end

    context 'with invalid headers' do
      it "doesn't destroy user" do
        expect do
          delete user_url(@user1), headers: invalid_token_header
        end.to change(User, :count).by(0)
      end

      it 'renders a unsuccessful response' do
        delete user_url(@user1), headers: invalid_token_header
        expect(response).not_to be_successful
      end
    end
  end
end
