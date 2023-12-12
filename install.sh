!/bin/bash
export PATH=/usr/local/bin:$PATH

echo -e "\n\n🦄 BACKEND\n\n"
cd ~/Desktop
rails new backtest --api --database=postgresql --skip-test-unit
cd backtest
rails db:drop db:create
bundle add rack-cors bcrypt jwt pry
bundle add rspec-rails --group "development, test"
bundle add database_cleaner-active_record --group "test"
bundle
rails active_storage:install
rails generate rspec:install
rails db:migrate
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets ~/Desktop/backtest/app/
puravida spec/fixtures/files
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/office-avatars/* ~/Desktop/backtest/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/cars/* ~/Desktop/backtest/spec/fixtures/files/
cat <<'EOF' | puravida config/initializers/cors.rb ~
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "*"
    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end
~
EOF
echo -e "\n\n🦄 Health Controller\n\n"
rails g controller health index
cat <<'EOF' | puravida app/controllers/health_controller.rb ~
class HealthController < ApplicationController
  def index
    render json: { status: 'online' }
  end
end
~
EOF
cat <<'EOF' | puravida spec/requests/health_spec.rb ~
# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API Testing" do
  describe "GET /health" do
    it "returns success" do
      get("/health")

      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)['status']).to eq('online')
    end

  end

end
~
EOF
cat <<'EOF' | puravida config/routes.rb ~
Rails.application.routes.draw do
  get "health", to: "health#index"
end
~
EOF
rspec

echo -e "\n\n🦄  Users\n\n"
rails g scaffold user name email avatar:attachment admin:boolean password_digest
MIGRATION_FILE=$(find /Users/mmcdermott/Desktop/backtest/db/migrate -name "*_create_users.rb")
sed -i -e 3,10d $MIGRATION_FILE
awk 'NR==3 {print "\t\tcreate_table :users do |t|\n\t\t\tt.string :name, null: false\n\t\t\tt.string :email, null: false, index: { unique: true }\n\t\t\tt.boolean :admin, default: false\n\t\t\tt.string :password_digest\n\t\t\tt.timestamps\n\t\tend"} 1' $MIGRATION_FILE > temp.txt && mv temp.txt $MIGRATION_FILE
rails db:migrate
cat <<'EOF' | puravida app/models/user.rb ~
class User < ApplicationRecord
  has_one_attached :avatar
  has_secure_password
  validates :email, format: { with: /\A(.+)@(.+)\z/, message: "Email invalid" }, uniqueness: { case_sensitive: false }, length: { minimum: 4, maximum: 254 }
end
~
EOF
rm -rf test
cat <<'EOF' | puravida spec/rails_helper.rb ~
require 'spec_helper'
require 'database_cleaner/active_record'
ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'
abort("The Rails environment is running in production mode!") if Rails.env.production?
require 'rspec/rails'
begin
  ActiveRecord::Migration.maintain_test_schema!
rescue ActiveRecord::PendingMigrationError => e
  abort e.to_s.strip
end
RSpec.configure do |config|
  config.fixture_path = Rails.root.join('spec/fixtures')
  config.use_transactional_fixtures = true
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
end

def token_from_email_password(email,password)
  post "/login", params: { email: email, password: password }
  JSON.parse(response.body)['data']
end
~
EOF
rails g rspec:scaffold users
rails g rspec:model user
cat <<'EOF' | puravida spec/models/user_spec.rb ~
require 'rails_helper'
require 'database_cleaner/active_record'
RSpec.describe User, type: :model do
  let(:mock_1_valid_create_params) {{ name: "First1 Last1", email: "one@mail.com", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:mock_1_invalid_create_params_email_poorly_formed) {{ name: "", email: "not_an_email", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  it "is valid with valid attributes" do
    expect(User.new(mock_1_valid_create_params)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(User.new(mock_1_invalid_create_params_email_poorly_formed)).to_not be_valid
  end
end
~
EOF
rspec


cat <<'EOF' | puravida app/controllers/application_controller.rb ~
class ApplicationController < ActionController::API
  SECRET_KEY_BASE = Rails.application.credentials.secret_key_base

  def encode_token(payload)
    JWT.encode payload, SECRET_KEY_BASE, 'HS256'
  end

  def decoded_token
    if auth_header and auth_header.split(' ')[0] == "Bearer"
      token = auth_header.split(' ')[1]
      begin
        JWT.decode token, SECRET_KEY_BASE, true, { algorithm: 'HS256' }
      rescue JWT::DecodeError
        []
      end
    end
  end

  # We don't want to send the whole user record from the database to the frontend, so we only send what we need.
  # The db user row has password_digest (unsafe) and created_at and updated_at (extraneous).
  # We also change avatar from a weird active_storage object to just the avatar url before it gets to the frontend.
  def prep_raw_user(user)
    avatar = user.avatar.present? ? url_for(user.avatar) : nil
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    user
  end

  private 

  def auth_header
    request.headers['Authorization']
  end
end

  private 

  def auth_header
    request.headers['Authorization']
  end
~
EOF

cat <<'EOF' | puravida app/controllers/users_controller.rb ~
class UsersController < ApplicationController
  before_action :set_user, only: %i[ show update destroy ]

  # GET /users
  def index
    @users = User.all.map { |user| prep_raw_user(user) }
    render json: @users
  end

  # GET /users/1
  def show
    render json: prep_raw_user(@user)
  end

  # POST /users
  def create
    @user = User.new(user_params)
    if @user.save
      render json: prep_raw_user(@user), status: :created, location: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /users/1
  def update
    if @user.update(user_params)
      render json: prep_raw_user(@user)
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/1
  def destroy
    @user.destroy
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Only allow a list of trusted parameters through.
    def user_params
      params['avatar'] = params['avatar'].blank? ? nil : params['avatar'] # if no avatar is chosen on signup page, params['avatar'] comes in as a blank string, which throws a 500 error at User.new(user_params). This changes any params['avatar'] blank string to nil, which is fine in User.new(user_params).
      params.permit(:name, :email, :avatar, :admin, :password)
    end
    
end
~
EOF


cat <<'EOF' | puravida spec/fixtures/users.yml ~
michael:
  name: Michael Scott
  email: michaelscott@dundermifflin.com
  password_digest: <%= BCrypt::Password.create('password') %>
  admin: true

jim:
  name: Jim Halpert
  email: jimhalpert@dundermifflin.com
  password_digest: <%= BCrypt::Password.create('password') %>
  admin: false

pam:
  name: Pam Beesly
  email: pambeesly@dundermifflin.com
  password_digest: <%= BCrypt::Password.create('password') %>
  admin: false

ryan:
  name: Ryan Howard
  email: ryanhoward@dundermifflin.com
  password_digest: <%= BCrypt::Password.create('password') %>
  admin: true
~
EOF
cat <<'EOF' | puravida config/storage.yml ~
test:
  service: Disk
  root: <%= Rails.root.join("tmp/storage") %>

test_fixtures:
  service: Disk
  root: <%= Rails.root.join("tmp/storage_fixtures") %>

local:
  service: Disk
  root: <%= Rails.root.join("storage") %>
~
EOF

# cat <<'EOF' | puravida app/controllers/application_controller.rb ~
# class ApplicationController < ActionController::API
#   SECRET_KEY_BASE = Rails.application.credentials.secret_key_base

#   def encode_token(payload)
#     JWT.encode payload, SECRET_KEY_BASE, 'HS256'
#   end

#   def decoded_token
#     if auth_header and auth_header.split(' ')[0] == "Bearer"
#       token = auth_header.split(' ')[1]
#       begin
#         JWT.decode token, SECRET_KEY_BASE, true, { algorithm: 'HS256' }
#       rescue JWT::DecodeError
#         []
#       end
#     end
#   end

#   # We don't want to send the whole user record from the database to the frontend, so we only send what we need.
#   # The db user row has password_digest (unsafe) and created_at and updated_at (extraneous).
#   # We also change avatar from a weird active_storage object to just the avatar url before it gets to the frontend.
#   def prep_raw_user(user)
#     avatar = user.avatar.present? ? url_for(user.avatar) : nil
#     user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
#     user['avatar'] = avatar
#     user
#   end

#   private 

#   def auth_header
#     request.headers['Authorization']
#   end
# end
# ~
# EOF
cat <<'EOF' | puravida spec/requests/users_spec.rb ~
# frozen_string_literal: true
require 'rails_helper'

RSpec.describe "/users", type: :request do
  fixtures :users
  let(:user_valid_create_params_mock_1) {{ name: "First1 Last1", email: "one@mail.com", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:user_invalid_create_params_email_poorly_formed_mock_1) {{ name: "", email: "not_an_email", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:valid_user_update_attributes) {{ name: "UpdatedName" }}
  let(:invalid_user_update_attributes) {{ email: "not_an_email" }}
  
  before :each do
    @user1 = users(:michael)
    avatar1 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'michael-scott.png'),'image/png')
    @user1.avatar.attach(avatar1)
    @user2 = users(:jim)
    avatar2 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'jim-halpert.png'),'image/png')
    @user2.avatar.attach(avatar2)
  end

  describe "GET /index" do
    it "renders a successful response" do
      get users_url
      expect(response).to be_successful
    end

    it "gets four users" do
      get users_url
      expect(JSON.parse(response.body).length).to eq 4
    end

    it "gets first users' correct details" do
      get users_url
      users = JSON.parse(response.body)
      michael = users.find { |user| user['email'] == "michaelscott@dundermifflin.com" }
      expect(michael['name']).to eq "Michael Scott"
      expect(michael['email']).to eq "michaelscott@dundermifflin.com"
      expect(michael['admin']).to eq true
      expect(michael['avatar']).to be_kind_of(String)
      expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
      expect(michael['password']).to be_nil
      expect(michael['password_digest']).to be_nil
    end

    it "gets second users' correct details" do
      get users_url
      users = JSON.parse(response.body)
      jim = users.find { |user| user['email'] == "jimhalpert@dundermifflin.com" }
      expect(jim['name']).to eq "Jim Halpert"
      expect(jim['email']).to eq "jimhalpert@dundermifflin.com"
      expect(jim['admin']).to be_nil or eq false
      expect(jim['avatar']).to be_kind_of(String)
      expect(jim['avatar']).to match(/http.*\jim-halpert\.png/)
      expect(jim['password']).to be_nil
      expect(jim['password_digest']).to be_nil
    end

  end

  describe "GET /show" do
    it "renders a successful response" do
      get user_url(@user1)
      expect(response).to be_successful
    end
    it "gets users' correct details" do
      get user_url(@user1)
      michael = JSON.parse(response.body)
      expect(michael['name']).to eq "Michael Scott"
      expect(michael['email']).to eq "michaelscott@dundermifflin.com"
      expect(michael['admin']).to eq true
      expect(michael['avatar']).to be_kind_of(String)
      expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
      expect(michael['password']).to be_nil
      expect(michael['password_digest']).to be_nil
    end
  end

  describe "POST /users" do
    context "with valid parameters" do
      it "creates a new User" do
        expect {
          post users_url, params: user_valid_create_params_mock_1
        }.to change(User, :count).by(1)
      end

      it "renders a successful response" do
        post users_url, params: user_valid_create_params_mock_1
        expect(response).to be_successful
      end

      it "sets correct user details" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user['name']).to eq "First1 Last1"
        expect(user['email']).to eq "one@mail.com"
        expect(user['admin']).to eq(false).or(be_nil)
        expect(user['avatar']).to be_nil
        expect(user['password']).to be_nil
        expect(user['password_digest']).to be_kind_of(String)
      end

      it "attaches user avatar" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user.avatar.attached?).to eq(true)
      end
    end

    context "with invalid parameters (email poorly formed)" do
      it "does not create a new User" do
        expect {
          post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        }.to change(User, :count).by(0)
      end
    
      it "renders a 422 response" do
        post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        expect(response).to have_http_status(:unprocessable_entity)
      end  
    end
  end

  describe "PATCH /update" do
    context "with valid parameters" do

      it "updates the requested user attribute" do
        patch user_url(@user1), params: valid_user_update_attributes
        @user1.reload
        expect(@user1.name).to eq("UpdatedName")
      end

      it "doesn't change the other user attributes" do
        patch user_url(@user1), params: valid_user_update_attributes
        @user1.reload
        expect(@user1['email']).to eq "michaelscott@dundermifflin.com"
        expect(@user1['admin']).to eq true
        expect(@user1['avatar']).to be_nil
        expect(@user1['password']).to be_nil
        expect(@user1['password_digest']).to be_kind_of(String)
      end

      it "is successful" do
        patch user_url(@user1), params: valid_user_update_attributes
        @user1.reload
        expect(response).to be_successful
      end
    end

    context "with invalid parameters" do
    
       it "renders a 422 response" do
         patch user_url(@user1), params: invalid_user_update_attributes
         expect(response).to have_http_status(:unprocessable_entity)
       end
    
    end
  end

  describe "DELETE /destroy" do
    it "destroys the requested user" do
      expect {
        delete user_url(@user1)
      }.to change(User, :count).by(-1)
    end

    it "renders a successful response" do
      delete user_url(@user1)
      expect(response).to be_successful
    end
  end

end
~
EOF
rspec



echo -e "\n\n🦄  /login Route (Authentications Controller)\n\n"
rails g controller Authentications
cat <<'EOF' | puravida app/controllers/authentications_controller.rb ~
class AuthenticationsController < ApplicationController
  skip_before_action :require_login
  
  def create
    user = User.find_by(email: params[:email])
    if user && user.authenticate(params[:password])
      payload = { user_id: user.id, email: user.email }
      token = encode_token(payload)
      render json: { data: token, status: 200, message: 'You are logged in successfully' }
    else
      response_unauthorized
    end
  end
end
~
EOF
cat <<'EOF' | puravida spec/requests/authentications_spec.rb ~
# frozen_string_literal: true
require 'rails_helper'

RSpec.describe "/login", type: :request do
  let(:valid_login_params) { { email: "michaelscott@dundermifflin.com",  password: "password" } }
  let(:invalid_login_params) { { email: "michaelscott@dundermifflin.com",  password: "testing" } }
  let(:create_user_params) { { name: "Michael Scott", email: "michaelscott@dundermifflin.com", admin: "true", password: "password" }}
  describe "POST /login" do
    context "without params" do
      it "returns unauthorized" do
        post "/login"
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end
  describe "POST /login" do
    context "with invalid params" do
      it "returns unauthorized" do
        post "/login", params: invalid_login_params
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end
  describe "POST /login" do
    context "with valid params" do
      it "returns unauthorized" do
        user = User.create(create_user_params)
        post "/login", params: valid_login_params
        expect(response).to have_http_status(:success)
        expect(JSON.parse(response.body)['message']).to eq "You are logged in successfully"
        expect(JSON.parse(response.body)['data']).to match(/^(?:[\w-]*\.){2}[\w-]*$/)
      end
    end
  end
end
~
EOF
cat <<'EOF' | puravida app/controllers/users_controller.rb ~
class UsersController < ApplicationController
  before_action :set_user, only: %i[ show update destroy ]
  skip_before_action :require_login, only: :create

  # GET /users
  def index
    @users = User.all.map { |user| prep_raw_user(user) }
    render json: @users
  end

  # GET /users/1
  def show
    render json: prep_raw_user(@user)
  end

  # POST /users
  def create
    @user = User.new(user_params)
    if @user.save
      render json: prep_raw_user(@user), status: :created, location: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /users/1
  def update
    if @user.update(user_params)
      render json: prep_raw_user(@user)
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/1
  def destroy
    @user.destroy
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Only allow a list of trusted parameters through.
    def user_params
      params['avatar'] = params['avatar'].blank? ? nil : params['avatar'] # if no avatar is chosen on signup page, params['avatar'] comes in as a blank string, which throws a 500 error at User.new(user_params). This changes any params['avatar'] blank string to nil, which is fine in User.new(user_params).
      params.permit(:name, :email, :avatar, :admin, :password)
    end
    
end
~
EOF
cat <<'EOF' | puravida config/routes.rb ~
Rails.application.routes.draw do
  resources :users
  get "health", to: "health#index"
  post "login", to: "authentications#create"
  get "me", to: "application#user_from_token"
end
~
EOF

echo -e "\n\n🦄  /me Route (Application Controller)\n\n"
cat <<'EOF' | puravida app/controllers/application_controller.rb ~
class ApplicationController < ActionController::API
  SECRET_KEY_BASE = Rails.application.credentials.secret_key_base
  before_action :require_login
  rescue_from Exception, with: :response_internal_server_error

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
    if decoded_token.present?
      user_id = decoded_token[0]['user_id']
      @user = User.find_by(id: user_id)
    else
      nil
    end
  end

  def encode_token(payload)
    JWT.encode payload, SECRET_KEY_BASE, 'HS256'
  end

  def decoded_token
    if auth_header and auth_header.split(' ')[0] == "Bearer"
      token = auth_header.split(' ')[1]
      begin
        JWT.decode token, SECRET_KEY_BASE, true, { algorithm: 'HS256' }
      rescue JWT::DecodeError
        []
      end
    end
  end

  def response_unauthorized
    render status: 401, json: { status: 401, message: 'Unauthorized' }
  end
  
  def response_internal_server_error
    render status: 500, json: { status: 500, message: 'Internal Server Error' }
  end

  # We don't want to send the whole user record from the database to the frontend, so we only send what we need.
  # The db user row has password_digest (unsafe) and created_at and updated_at (extraneous).
  # We also change avatar from a weird active_storage object to just the avatar url before it gets to the frontend.
  def prep_raw_user(user)
    avatar = user.avatar.present? ? url_for(user.avatar) : nil
    # cars = Car.where(user_id: user.id).map { |car| car.id }
    # documents = Document.where(car_id: cars).map { |document| document.id }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    # user['car_ids'] = cars
    # user['document_ids'] = documents
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    # documents = Document.where(car_id: car.id)
    # documents = documents.map { |document| document.slice(:id,:name,:description,:car_id) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:description)
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    # car['documents'] = documents
    car
  end

  def prep_raw_document(document)
    car_id = document.car_id
    car = Car.find(car_id)
    user = User.find(car.user_id)
    image = document.image.present? ? url_for(document.image) : nil
    document = document.slice(:id,:name,:description)
    document['carId'] = car_id
    document['carName'] = car.name
    document['carDescription'] = car.description
    document['userId'] = user.id
    document['userName'] = user.name
    document['image'] = image
    document
  end
  
  private 
  
    def auth_header
      request.headers['Authorization']
    end

end
~
EOF
cat <<'EOF' | puravida spec/requests/application_spec.rb ~
# frozen_string_literal: true
require 'rails_helper'
require 'spec_helper'

RSpec.describe "/me", type: :request do
  fixtures :users
  let(:valid_headers) {{ Authorization: "Bearer " + @token }}
  let(:invalid_token_header) {{ Authorization: "Bearer xyz" }}
  let(:poorly_formed_header) {{ Authorization: "Bear " + @token }}
  
  before :all do
    @token = token_from_email_password("michaelscott@dundermifflin.com", "password")
  end
  
  describe "GET /me" do

    context "without auth header" do
      it "returns http success" do
        get "/me"
        expect(response).to have_http_status(:unauthorized)
      end
    end
    
    context "with invalid token header" do
      it "returns http success" do
        get "/me", headers: invalid_token_header
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context "with valid token, but poorly formed auth header" do
      it "returns http success" do
        get "/me", headers: poorly_formed_header
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context "with valid auth header" do
      it "returns http success" do
        get "/me", headers: valid_headers
        expect(response).to have_http_status(:success)
      end
    end
  end
end
~
EOF

echo -e "\n\n🦄  Update users_spec.rb For Auth\n\n"
cat <<'EOF' | puravida spec/requests/users_spec.rb ~
# frozen_string_literal: true
require 'rails_helper'
require 'spec_helper'

RSpec.describe "/users", type: :request do
  fixtures :users
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:admin_2_headers) {{ Authorization: "Bearer " + @ryan_token }}
  let(:invalid_token_header) {{ Authorization: "Bearer xyz" }}
  let(:poorly_formed_header) {{ Authorization: "Bear " + @michael_token }}
  let(:user_valid_create_params_mock_1) {{ name: "First1 Last1", email: "one@mail.com", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:user_invalid_create_params_email_poorly_formed_mock_1) {{ name: "", email: "not_an_email", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:valid_user_update_attributes) {{ name: "UpdatedName" }}
  let(:invalid_user_update_attributes) {{ email: "not_an_email" }}
  
  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
    @ryan_token = token_from_email_password("ryanhoward@dundermifflin.com", "password")
  end

  before :each do
    @user1 = users(:michael)
    avatar1 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'michael-scott.png'),'image/png')
    @user1.avatar.attach(avatar1)
    @user2 = users(:jim)
    avatar2 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'jim-halpert.png'),'image/png')
    @user2.avatar.attach(avatar2)
  end

  describe "GET /index" do
    context "with valid headers" do
      it "renders a successful response" do
        get users_url, headers: valid_headers
        expect(response).to be_successful
      end

      it "gets four users" do
        get users_url, headers: valid_headers
        expect(JSON.parse(response.body).length).to eq 4
      end

      it "gets first users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        michael = users.find { |user| user['email'] == "michaelscott@dundermifflin.com" }
        expect(michael['name']).to eq "Michael Scott"
        expect(michael['email']).to eq "michaelscott@dundermifflin.com"
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
      end

      it "gets second users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        jim = users.find { |user| user['email'] == "jimhalpert@dundermifflin.com" }
        expect(jim['name']).to eq "Jim Halpert"
        expect(jim['email']).to eq "jimhalpert@dundermifflin.com"
        expect(jim['admin']).to be_nil or eq false
        expect(jim['avatar']).to be_kind_of(String)
        expect(jim['avatar']).to match(/http.*\jim-halpert\.png/)
        expect(jim['password']).to be_nil
        expect(jim['password_digest']).to be_nil
      end
    end

    context "with invalid headers" do
      it "renders an unsuccessful response" do
        get users_url, headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end

  end

  describe "GET /show" do
    context "with valid headers" do
      it "renders a successful response" do
        get user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end
      it "gets users' correct details" do
        get user_url(@user1), headers: valid_headers
        michael = JSON.parse(response.body)
        expect(michael['name']).to eq "Michael Scott"
        expect(michael['email']).to eq "michaelscott@dundermifflin.com"
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
      end
    end
    context "with invalid headers" do
      it "renders an unsuccessful response" do
        get user_url(@user1), headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end
  end

  describe "POST /users" do
    context "with valid parameters" do
      it "creates a new User" do
        expect {
          post users_url, params: user_valid_create_params_mock_1
        }.to change(User, :count).by(1)
      end

      it "renders a successful response" do
        post users_url, params: user_valid_create_params_mock_1
        expect(response).to be_successful
      end

      it "sets correct user details" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user['name']).to eq "First1 Last1"
        expect(user['email']).to eq "one@mail.com"
        expect(user['admin']).to eq(false).or(be_nil)
        expect(user['avatar']).to be_nil
        expect(user['password']).to be_nil
        expect(user['password_digest']).to be_kind_of(String)
      end

      it "attaches user avatar" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user.avatar.attached?).to eq(true)
      end
    end

    context "with invalid parameters (email poorly formed)" do
      it "does not create a new User" do
        expect {
          post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        }.to change(User, :count).by(0)
      end
    
      it "renders a 422 response" do
        post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        expect(response).to have_http_status(:unprocessable_entity)
      end  
    end
  end

  describe "PATCH /update" do
    context "with valid parameters and headers" do

      it "updates the requested user attribute" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(@user1.name).to eq("UpdatedName")
      end

      it "doesn't change the other user attributes" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(@user1['email']).to eq "michaelscott@dundermifflin.com"
        expect(@user1['admin']).to eq true
        expect(@user1['avatar']).to be_nil
        expect(@user1['password']).to be_nil
        expect(@user1['password_digest']).to be_kind_of(String)
      end

      it "is successful" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(response).to be_successful
      end
    end

    context "with invalid parameters but valid headers" do
       it "renders a 422 response" do
         patch user_url(@user1), params: invalid_user_update_attributes, headers: valid_headers
         expect(response).to have_http_status(:unprocessable_entity)
       end
    end

    context "with valid parameters but invalid headers" do
       it "renders a 401 response" do
         patch user_url(@user1), params: valid_user_update_attributes, headers: invalid_token_header
         expect(response).to have_http_status(:unauthorized)
       end
    end

  end

  describe "DELETE /destroy" do
    context "with valid headers" do
      it "destroys the requested user" do
        expect {
          delete user_url(@user1), headers: valid_headers
        }.to change(User, :count).by(-1)
      end

      it "renders a successful response" do
        delete user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end
    end

    context "with invalid headers" do
      it "doesn't destroy user" do
        expect {
          delete user_url(@user1), headers: invalid_token_header
        }.to change(User, :count).by(0)
      end

      it "renders a unsuccessful response" do
        delete user_url(@user1), headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end
  end

end
~
EOF

echo -e "\n\n🦄  Update Health Controller For Auth\n\n"
cat <<'EOF' | puravida app/controllers/health_controller.rb ~
class HealthController < ApplicationController
  skip_before_action :require_login
  def index
    render json: { status: 'online' }
  end
end
~
EOF
rspec

echo -e "\n\n🦄  Cars (Backend)\n\n"
rails g scaffold car name description image:attachment user:references
find /Users/mmcdermott/Desktop/backtest/db/migrate/ -name "*_create_cars.rb" -exec sed -i '' "s/foreign_key: true/foreign_key: {on_delete: :cascade}/g" {} +
rails db:migrate
cat <<'EOF' | puravida app/models/car.rb ~
class Car < ApplicationRecord
  belongs_to :user
  has_one_attached :image
  validates :name, presence: true, allow_blank: false, length: { minimum: 4, maximum: 254 }
end
~
EOF

cat <<'EOF' | puravida app/controllers/application_controller.rb ~
class ApplicationController < ActionController::API
  SECRET_KEY_BASE = Rails.application.credentials.secret_key_base
  before_action :require_login
  rescue_from Exception, with: :response_internal_server_error

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
    if decoded_token.present?
      user_id = decoded_token[0]['user_id']
      @user = User.find_by(id: user_id)
    else
      nil
    end
  end

  def encode_token(payload)
    JWT.encode payload, SECRET_KEY_BASE, 'HS256'
  end

  def decoded_token
    if auth_header and auth_header.split(' ')[0] == "Bearer"
      token = auth_header.split(' ')[1]
      begin
        JWT.decode token, SECRET_KEY_BASE, true, { algorithm: 'HS256' }
      rescue JWT::DecodeError
        []
      end
    end
  end

  def response_unauthorized
    render status: 401, json: { status: 401, message: 'Unauthorized' }
  end
  
  def response_internal_server_error
    render status: 500, json: { status: 500, message: 'Internal Server Error' }
  end

  # We don't want to send the whole user record from the database to the frontend, so we only send what we need.
  # The db user row has password_digest (unsafe) and created_at and updated_at (extraneous).
  # We also change avatar from a weird active_storage object to just the avatar url before it gets to the frontend.
  def prep_raw_user(user)
    avatar = user.avatar.present? ? url_for(user.avatar) : nil
    car_ids = Car.where(user_id: user.id).map { |car| car.id }
    cars = Car.where(user_id: user.id).map { |car| prep_raw_car(car) }
    # documents = Document.where(car_id: cars).map { |document| document.id }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    user['car_ids'] = car_ids
    user['cars'] = cars
    # user['document_ids'] = documents
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    # documents = Document.where(car_id: car.id)
    # documents = documents.map { |document| document.slice(:id,:name,:description,:car_id) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:description)
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    # car['documents'] = documents
    car
  end

  def prep_raw_document(document)
    car_id = document.car_id
    car = Car.find(car_id)
    user = User.find(car.user_id)
    image = document.image.present? ? url_for(document.image) : nil
    document = document.slice(:id,:name,:description)
    document['carId'] = car_id
    document['carName'] = car.name
    document['carDescription'] = car.description
    document['userId'] = user.id
    document['userName'] = user.name
    document['image'] = image
    document
  end
  
  private 
  
    def auth_header
      request.headers['Authorization']
    end

end
~
EOF

cat <<'EOF' | puravida app/controllers/cars_controller.rb ~
class CarsController < ApplicationController
  before_action :set_car, only: %i[ show update destroy ]

  # GET /cars
  def index
    if params['user_id'].present?
      @cars = Car.where(user_id: params['user_id']).map { |car| prep_raw_car(car) }
    else
      @cars = Car.all.map { |car| prep_raw_car(car) }
    end
    render json: @cars
  end

  # GET /cars/1
  def show
    render json: prep_raw_car(@car)
  end

  # POST /cars
  def create
    create_params = car_params
    create_params['image'] = params['image'].blank? ? nil : params['image'] # if no image is chosen on new car page, params['image'] comes in as a blank string, which throws a 500 error at User.new(user_params). This changes any params['avatar'] blank string to nil, which is fine in User.new(user_params).
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
      params.permit(:id, :name, :description, :image, :user_id)
    end
end
~
EOF
cat <<'EOF' | puravida spec/fixtures/cars.yml ~
fiat:
  name: Michael's Fiat 500
  description: Michael's Fiat 500 (description)
  user: michael

civic:
  name: Michael's Honda Civic
  description: Michael's Honda Civic (description)
  user: michael

elantra:
  name: Jim's Hyundai Elantra
  description: Jim's Hyundai Elantra (description)
  user: jim

leaf:
  name: Jim's Nissan Leaf
  description: Jim's Nissan Leaf (description)
  user: jim

scion:
  name: Pam's Scion
  description: Pam's Scion (description)
  user: jim

camry:
  name: Pam's Toyota Camry
  description: Pam's Toyota Camry (description)
  user: pam
~
EOF
cat <<'EOF' | puravida spec/models/car_spec.rb ~
require 'rails_helper'

RSpec.describe "/cars", type: :request do
  fixtures :users
  fixtures :cars
  let(:valid_attributes) {{ name: "test1", description: "test1", user_id: User.find_by(email: "michaelscott@dundermifflin.com").id }}
  let(:invalid_attributes) {{ name: "", description: "invalid_attributes" }}
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}

  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
  end

  it "is valid with valid attributes" do
    expect(Car.new(valid_attributes)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(Car.new(invalid_attributes)).to_not be_valid
  end

end
~
EOF

cat <<'EOF' | puravida spec/requests/cars_spec.rb ~
require 'rails_helper'

RSpec.describe "/cars", type: :request do
  fixtures :users
  fixtures :cars
  let(:valid_attributes) {{ name: "test1", description: "test1", user_id: User.find_by(email: "michaelscott@dundermifflin.com").id }}
  let(:invalid_attributes) {{ name: "", description: "invalid_attributes" }}
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}

  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
    @ryan_token = token_from_email_password("ryanhoward@dundermifflin.com", "password")
  end

  before :each do
    @fiat = cars(:fiat)
    @fiat.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-500.jpg'),'image/jpeg'))
    @civic = cars(:civic)
    @civic.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'honda-civic.jpg'),'image/jpeg'))
    @elantra = cars(:elantra)
    @elantra.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'hyundai-elantra.jpg'),'image/jpeg'))
    @leaf = cars(:leaf)
    @leaf.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'nissan-leaf.jpg'),'image/jpeg'))
    @scion = cars(:scion)
    @scion.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion.jpg'),'image/jpeg'))
    @camry = cars(:camry)
    @camry.image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'toyota-camry.jpg'),'image/jpeg'))
  end

  describe "GET /index" do
    it "renders a successful response" do
      get cars_url, headers: valid_headers
      expect(response).to be_successful
    end
    it "gets two cars a successful response" do
      get cars_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 6
    end
    it "first car has correct properties" do
      get cars_url, headers: valid_headers
      cars = JSON.parse(response.body)
      fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
      expect(fiat['name']).to eq "Michael's Fiat 500"
      expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
      expect(fiat['userName']).to eq "Michael Scott"
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
    end
    it "second car has correct properties" do
      get cars_url, headers: valid_headers
      cars = JSON.parse(response.body)
      elantra = cars.find { |car| car['name'] == "Jim's Hynadai Elantra" }
      expect(elantra['name']).to eq "Jim's Hynadai Elantra"
      expect(elantra['description']).to eq "Jim's Hynadai Elantra (description)"
      expect(elantra['userName']).to eq "Jim Halpert"
      expect(elantra['image']).to be_kind_of(String)
      expect(elantra['image']).to match(/http.*hyundai-elantra\.jpg/)
    end

  end

  describe "GET /show" do
    it "renders a successful response" do
      car = cars(:fiat)
      get car_url(car), headers: valid_headers
      expect(response).to be_successful
    end
    it "gets correct car properties" do
      car = cars(:fiat)
      get car_url(car), headers: valid_headers
      fiat = JSON.parse(response.body)
      expect(fiat['name']).to eq "Michael's Fiat 500"
      expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
      expect(fiat['userName']).to eq "Michael Scott"
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
    end
  end

  describe "POST /create" do
    context "with valid parameters" do
      it "creates a new Car" do
        expect { post cars_url, params: valid_attributes, headers: valid_headers, as: :json
        }.to change(Car, :count).by(1)
      end

      it "renders a JSON response with the new car" do
        post cars_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end

    context "with invalid parameters" do
      it "does not create a new Car" do
        expect {
          post cars_url, params: invalid_attributes, headers: valid_headers, as: :json
        }.to change(Car, :count).by(0)
      end

      it "renders a JSON response with errors for the new car" do
        post cars_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end
  end

  describe "PATCH /update" do
    context "with valid parameters" do
      let(:new_attributes) {{ name: "UpdatedName"}}

      it "updates the requested car" do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        car.reload
        expect(car.name).to eq("UpdatedName")
      end

      it "renders a JSON response with the car" do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including("application/json"))
      end

      it "car's other properties are still correct" do
        car = cars(:fiat)
        patch car_url(car), params: new_attributes, headers: valid_headers, as: :json
        fiat = JSON.parse(response.body)
        expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
      end

    end

    context "with invalid parameters" do
      it "renders a JSON response with errors for the car" do
        car = cars(:fiat)
        patch car_url(car), params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end
  end

  describe "DELETE /destroy" do
    it "destroys the requested car" do
      car = Car.create! valid_attributes
      expect { delete car_url(car), headers: valid_headers, as: :json
      }.to change(Car, :count).by(-1)
    end
  end
end
~
EOF
cat <<'EOF' | puravida spec/requests/users_spec.rb ~
# frozen_string_literal: true
require 'rails_helper'
require 'spec_helper'

RSpec.describe "/users", type: :request do
  fixtures :users
  fixtures :cars
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:admin_2_headers) {{ Authorization: "Bearer " + @ryan_token }}
  let(:invalid_token_header) {{ Authorization: "Bearer xyz" }}
  let(:poorly_formed_header) {{ Authorization: "Bear " + @michael_token }}
  let(:user_valid_create_params_mock_1) {{ name: "First1 Last1", email: "one@mail.com", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:user_invalid_create_params_email_poorly_formed_mock_1) {{ name: "", email: "not_an_email", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:valid_user_update_attributes) {{ name: "UpdatedName" }}
  let(:invalid_user_update_attributes) {{ email: "not_an_email" }}
  
  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
    @ryan_token = token_from_email_password("ryanhoward@dundermifflin.com", "password")
  end

  before :each do
    @user1 = users(:michael)
    avatar1 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'michael-scott.png'),'image/png')
    @user1.avatar.attach(avatar1)
    @user2 = users(:jim)
    avatar2 = fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'jim-halpert.png'),'image/png')
    @user2.avatar.attach(avatar2)
    cars(:fiat).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-500.jpg'),'image/jpeg'))
    cars(:civic).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'honda-civic.jpg'),'image/jpeg'))
    cars(:elantra).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'hyundai-elantra.jpg'),'image/jpeg'))
    cars(:leaf).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'nissan-leaf.jpg'),'image/jpeg'))
    cars(:scion).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion.jpg'),'image/jpeg'))
    cars(:camry).image.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'toyota-camry.jpg'),'image/jpeg'))
  end

  describe "GET /index" do
    context "with valid headers" do
      it "renders a successful response" do
        get users_url, headers: valid_headers
        expect(response).to be_successful
      end

      it "gets four users" do
        get users_url, headers: valid_headers
        expect(JSON.parse(response.body).length).to eq 4
      end

      it "gets first users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        michael = users.find { |user| user['email'] == "michaelscott@dundermifflin.com" }
        car_ids = michael['car_ids']
        cars = michael['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(michael['name']).to eq "Michael Scott"
        expect(michael['email']).to eq "michaelscott@dundermifflin.com"
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['description']).to eq "Michael's Honda Civic (description)"
        expect(civic['userName']).to eq "Michael Scott"
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
      end

      it "gets second users' correct details" do
        get users_url, headers: valid_headers
        users = JSON.parse(response.body)
        jim = users.find { |user| user['email'] == "jimhalpert@dundermifflin.com" }
        car_ids = jim['car_ids']
        cars = jim['cars']
        elantra = cars.find { |car| car['name'] == "Jim's Hyundai Elantra" }
        leaf = cars.find { |car| car['name'] == "Jim's Nissan Leaf" }
        expect(jim['name']).to eq "Jim Halpert"
        expect(jim['email']).to eq "jimhalpert@dundermifflin.com"
        expect(jim['admin']).to be_nil or eq false
        expect(jim['avatar']).to be_kind_of(String)
        expect(jim['avatar']).to match(/http.*\jim-halpert\.png/)
        expect(jim['password']).to be_nil
        expect(jim['password_digest']).to be_nil
        expect(elantra['name']).to eq "Jim's Hyundai Elantra"
        expect(elantra['description']).to eq "Jim's Hyundai Elantra (description)"
        expect(elantra['userName']).to eq "Jim Halpert"
        expect(elantra['image']).to be_kind_of(String)
        expect(elantra['image']).to match(/http.*hyundai-elantra\.jpg/)
        expect(leaf['name']).to eq "Jim's Nissan Leaf"
        expect(leaf['description']).to eq "Jim's Nissan Leaf (description)"
        expect(leaf['userName']).to eq "Jim Halpert"
        expect(leaf['image']).to be_kind_of(String)
        expect(leaf['image']).to match(/http.*nissan-leaf\.jpg/)
      end
    end

    context "with invalid headers" do
      it "renders an unsuccessful response" do
        get users_url, headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end

  end

  describe "GET /show" do
    context "with valid headers" do
      it "renders a successful response" do
        get user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end
      it "gets users' correct details" do
        get user_url(@user1), headers: valid_headers
        michael = JSON.parse(response.body)
        car_ids = michael['car_ids']
        cars = michael['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(michael['name']).to eq "Michael Scott"
        expect(michael['email']).to eq "michaelscott@dundermifflin.com"
        expect(michael['admin']).to eq true
        expect(michael['avatar']).to be_kind_of(String)
        expect(michael['avatar']).to match(/http.*\michael-scott\.png/)
        expect(michael['password']).to be_nil
        expect(michael['password_digest']).to be_nil
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['description']).to eq "Michael's Honda Civic (description)"
        expect(civic['userName']).to eq "Michael Scott"
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
      end
    end
    context "with invalid headers" do
      it "renders an unsuccessful response" do
        get user_url(@user1), headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end
  end

  describe "POST /users" do
    context "with valid parameters" do
      it "creates a new User" do
        expect {
          post users_url, params: user_valid_create_params_mock_1
        }.to change(User, :count).by(1)
      end

      it "renders a successful response" do
        post users_url, params: user_valid_create_params_mock_1
        expect(response).to be_successful
      end

      it "sets correct user details" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user['name']).to eq "First1 Last1"
        expect(user['email']).to eq "one@mail.com"
        expect(user['admin']).to eq(false).or(be_nil)
        expect(user['avatar']).to be_nil
        expect(user['password']).to be_nil
        expect(user['password_digest']).to be_kind_of(String)
      end

      it "attaches user avatar" do
        post users_url, params: user_valid_create_params_mock_1
        user = User.order(:created_at).last
        expect(user.avatar.attached?).to eq(true)
        expect(url_for(user.avatar)).to be_kind_of(String)
        expect(url_for(user.avatar)).to match(/http.*michael-scott\.png/)
      end
    end

    context "with invalid parameters (email poorly formed)" do
      it "does not create a new User" do
        expect {
          post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        }.to change(User, :count).by(0)
      end
    
      it "renders a 422 response" do
        post users_url, params: user_invalid_create_params_email_poorly_formed_mock_1
        expect(response).to have_http_status(:unprocessable_entity)
      end  
    end
  end

  describe "PATCH /update" do
    context "with valid parameters and headers" do

      it "updates user's name" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(@user1.name).to eq("UpdatedName")
      end

      it "updates user's name in their cars" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        get user_url(@user1), headers: valid_headers
        user = JSON.parse(response.body)
        car_ids = user['car_ids']
        cars = user['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(fiat['userName']).to eq "UpdatedName"
        expect(civic['userName']).to eq "UpdatedName"
      end

      it "doesn't change the other user attributes" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        get user_url(@user1), headers: valid_headers
        user = JSON.parse(response.body)
        car_ids = user['car_ids']
        cars = user['cars']
        fiat = cars.find { |car| car['name'] == "Michael's Fiat 500" }
        civic = cars.find { |car| car['name'] == "Michael's Honda Civic" }
        expect(@user1['email']).to eq "michaelscott@dundermifflin.com"
        expect(@user1['admin']).to eq true
        expect(@user1['avatar']).to be_nil
        expect(@user1['password']).to be_nil
        expect(@user1['password_digest']).to be_kind_of(String)
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['description']).to eq "Michael's Fiat 500 (description)"
        expect(url_for(fiat['image'])).to be_kind_of(String)
        expect(url_for(fiat['image'])).to match(/http.*fiat-500\.jpg/)
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['description']).to eq "Michael's Honda Civic (description)"
        expect(url_for(civic['image'])).to be_kind_of(String)
        expect(url_for(civic['image'])).to match(/http.*honda-civic\.jpg/)
      end

      it "is successful" do
        patch user_url(@user1), params: valid_user_update_attributes, headers: valid_headers
        @user1.reload
        expect(response).to be_successful
      end
    end

    context "with invalid parameters but valid headers" do
       it "renders a 422 response" do
         patch user_url(@user1), params: invalid_user_update_attributes, headers: valid_headers
         expect(response).to have_http_status(:unprocessable_entity)
       end
    end

    context "with valid parameters but invalid headers" do
       it "renders a 401 response" do
         patch user_url(@user1), params: valid_user_update_attributes, headers: invalid_token_header
         expect(response).to have_http_status(:unauthorized)
       end
    end

  end

  describe "DELETE /destroy" do
    context "with valid headers" do
      it "destroys the requested user" do
        expect {
          delete user_url(@user1), headers: valid_headers
        }.to change(User, :count).by(-1)
      end

      it "renders a successful response" do
        delete user_url(@user1), headers: valid_headers
        expect(response).to be_successful
      end
    end

    context "with invalid headers" do
      it "doesn't destroy user" do
        expect {
          delete user_url(@user1), headers: invalid_token_header
        }.to change(User, :count).by(0)
      end

      it "renders a unsuccessful response" do
        delete user_url(@user1), headers: invalid_token_header
        expect(response).to_not be_successful
      end
    end
  end

end
~
EOF
rspec


# echo -e "\n\n🦄  Documents (Backend)\n\n"
# # rails g scaffold document name description image:attachment car:references
# rails g scaffold document name description image:attachment ref_id:integer ref_type
# rails db:migrate
# cat <<'EOF' | puravida app/controllers/documents_controller.rb ~
# class DocumentsController < ApplicationController
#   before_action :set_document, only: %i[ show update destroy ]

#   # GET /documents
#   def index
#     if params['user_id'].present?
#       @documents = Document.joins(car: [:user]).where(users: {id: params['user_id']}).map { |document| prep_raw_document(document) }
#     else
#       @documents = Document.all.map { |document| prep_raw_document(document) }
#     end
#     render json: @documents
#   end

#   # GET /documents/1
#   def show
#     render json: prep_raw_document(@document)
#   end

#   # POST /documents
#   def create
#     create_params = document_params
#     create_params['image'] = params['image'].blank? ? nil : params['image'] # if no image is chosen on new document page, params['image'] comes in as a blank string, which throws a 500 error at Document.new(create_params). This changes any params['avatar'] blank string to nil, which is fine in Document.new(create_params).
#     create_params['car_id'] = create_params['car_id'].to_i
#     @document = Document.new(create_params)
#     if @document.save
#       render json: prep_raw_document(@document), status: :created, location: @document
#     else
#       render json: @document.errors, status: :unprocessable_entity
#     end
#   end

#   # PATCH/PUT /documents/1
#   def update
#     if @document.update(document_params)
#       render json: prep_raw_document(@document)
#     else
#       render json: @document.errors, status: :unprocessable_entity
#     end
#   end

#   # DELETE /documents/1
#   def destroy
#     @document.destroy
#   end

#   private
#     # Use callbacks to share common setup or constraints between actions.
#     def set_document
#       @document = Document.find(params[:id])
#     end

#     # Only allow a list of trusted parameters through.
#     def document_params
#       params.permit(:id, :name, :description, :image, :car_id)
#     end
# end
# ~
# EOF
# cat <<'EOF' | puravida spec/requests/documents_spec.rb ~
# # frozen_string_literal: true
# require 'open-uri'
# require 'rails_helper'
# RSpec.describe "/cars", type: :request do
#   let(:valid_create_user_1_params) { { name: "Michael Scott", email: "michaelscott@dundermifflin.com", admin: "true", password: "password" } }
#   let(:user_1_attachment) { "/spec/fixtures/files/images/office-avatars/michael-scott.png" }
#   let(:user_1_image) { "michael-scott.png" }
#   let(:valid_create_user_2_params) { { name: "Jim Halpert", email: "jimhalpert@dundermifflin.com", admin: "false", password: "password" } }
#   let(:user_2_attachment) { "/spec/fixtures/files/images/office-avatars/jim-halpert.png" }
#   let(:user_2_image) { "jim-halpert.png" }
#   let(:invalid_create_user_1_params) { { name: "Michael Scott", email: "test", admin: "true", password: "password" } }
#   let(:invalid_create_user_2_params) { { name: "Jim Halpert", email: "test2", admin: "false", password: "password" } }
#   let(:valid_user_1_login_params) { { email: "michaelscott@dundermifflin.com",  password: "password" } }
#   let(:valid_user_2_login_params) { { email: "jimhalpert@dundermifflin.com",  password: "password" } }
#   let(:invalid_patch_params) { { email: "test" } }
#   let(:uploaded_image_path) { Rails.root.join '/spec/fixtures/files/images/office-avatars/michael-scott.png' }
#   let(:uploaded_image) { Rack::Test::UploadedFile.new uploaded_image_path, 'image/png' }

#   describe "GET /index" do
#     context "with valid auth header (non-admin user)" do
#       it "renders a successful response" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         image_filename = "allen-wrenches.jpg"
#         image_path = "#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"
#         open_image = URI.open(image_path)
#         car1.image.attach(io: open_image, filename: image_filename)
#         car1.save!
#         car2 = Car.create(name: "Bolts", description: "Michael's bolts", user_id: user1.id)
#         car2.save!
#         get cars_url, headers: header, as: :json
#         expect(response).to be_successful
#       end
      
#       it "gets two cars (one with image, one without)" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         car2 = Car.create(name: "Bolts", description: "Michael's bolts", user_id: user1.id)
#         car2.save!
#         header = header_from_user(user2,valid_user_2_login_params)
#         get cars_url, headers: header, as: :json
#         expect(response).to be_successful
#         expect(JSON.parse(response.body).length).to eq 2
#         expect(JSON.parse(response.body)[0]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[0]['name']).to eq("Wrenches")
#         expect(JSON.parse(response.body)[0]['description']).to eq("Michael's wrenches")
#         expect(JSON.parse(response.body)[0]['image']).to match(/http.*\/allen-wrenches\.jpg/)
#         expect(JSON.parse(response.body)[0]['userId']).to eq(user1.id)
#         expect(JSON.parse(response.body)[1]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[1]['name']).to eq("Bolts")
#         expect(JSON.parse(response.body)[1]['description']).to eq("Michael's bolts")
#         expect(JSON.parse(response.body)[1]['image']).to eq(nil)
#         expect(JSON.parse(response.body)[1]['userId']).to eq(user1.id)
#       end

#       it "gets user one's cars" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         car2 = Car.create(name: "Bolts", description: "Michael's bolts", user_id: user1.id)
#         car3 = Car.create(name: "test3", description: "test3", user_id: user2.id)
#         car3 = Car.create(name: "test4", description: "test4", user_id: user2.id)
#         header = header_from_user(user2,valid_user_2_login_params)
#         get cars_url, params: { user_id: user1.id }, headers: header
#         expect(response).to be_successful
#         expect(JSON.parse(response.body).length).to eq 2
#         expect(JSON.parse(response.body)[0]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[0]['name']).to eq("Wrenches")
#         expect(JSON.parse(response.body)[0]['description']).to eq("Michael's wrenches")
#         expect(JSON.parse(response.body)[0]['image']).to match(/http.*\/allen-wrenches\.jpg/)
#         expect(JSON.parse(response.body)[0]['userId']).to eq(user1.id)
#         expect(JSON.parse(response.body)[1]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[1]['name']).to eq("Bolts")
#         expect(JSON.parse(response.body)[1]['description']).to eq("Michael's bolts")
#         expect(JSON.parse(response.body)[1]['image']).to eq(nil)
#         expect(JSON.parse(response.body)[1]['userId']).to eq(user1.id)
#       end

#       it "gets user two's cars" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         car2 = Car.create(name: "Bolts", description: "Michael's bolts", user_id: user1.id)
#         car3 = Car.create(name: "test3", description: "test3", user_id: user2.id)
#         car3 = Car.create(name: "test4", description: "test4", user_id: user2.id)
#         header = header_from_user(user2,valid_user_2_login_params)
#         get cars_url, params: { user_id: user2.id }, headers: header
#         expect(response).to be_successful
#         expect(JSON.parse(response.body).length).to eq 2
#         expect(JSON.parse(response.body)[0]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[0]['name']).to eq("test3")
#         expect(JSON.parse(response.body)[0]['description']).to eq("test3")
#         expect(JSON.parse(response.body)[0]['userId']).to eq(user2.id)
#         expect(JSON.parse(response.body)[0]['image']).to eq(nil)
#         expect(JSON.parse(response.body)[1]).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)[1]['name']).to eq("test4")
#         expect(JSON.parse(response.body)[1]['description']).to eq("test4")
#         expect(JSON.parse(response.body)[1]['image']).to eq(nil)
#         expect(JSON.parse(response.body)[1]['userId']).to eq(user2.id)
#       end

#     end

#     context "with invalid auth header" do
#       it "renders a 401 response" do
#         User.create! valid_create_user_1_params
#         get cars_url, headers: invalid_auth_header, as: :json
#         expect(response).to have_http_status(401)
#       end
#       it "renders a 401 response" do
#         User.create! valid_create_user_1_params
#         get cars_url, headers: poorly_formed_header(valid_create_user_2_params), as: :json
#         expect(response).to have_http_status(401)
#       end
#     end
#   end

#   describe "GET /show" do
#     context "with valid auth header" do
#       it "renders a successful response" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         get car_url(car1), headers: header, as: :json
#         expect(response).to be_successful
#       end
#       it "gets one car (with image)" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         get car_url(car1), headers: header, as: :json
#         expect(JSON.parse(response.body)).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)['name']).to eq("Wrenches")
#         expect(JSON.parse(response.body)['description']).to eq("Michael's wrenches")
#         expect(JSON.parse(response.body)['image']).to match(/http.*\/allen-wrenches\.jpg/)
#         expect(JSON.parse(response.body)['userId']).to eq(user1.id)
#       end
#       it "gets one car (without avatar)" do
#         user1 = User.create! valid_create_user_1_params
#         user1.avatar.attach(io: URI.open("#{Rails.root}" + user_1_attachment), filename: user_1_image)
#         user1.save!
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car2 = Car.create(name: "Bolts", description: "Michael's bolts", user_id: user1.id)
#         car2.save!
#         get car_url(car2), headers: header, as: :json
#         expect(JSON.parse(response.body)).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)['name']).to eq("Bolts")
#         expect(JSON.parse(response.body)['description']).to eq("Michael's bolts")
#         expect(JSON.parse(response.body)['image']).to eq(nil)
#         expect(JSON.parse(response.body)['userId']).to eq(user1.id)
#       end
#     end
#     context "with invalid auth header" do
#       it "renders a 401 response" do
#         user1 = User.create! valid_create_user_1_params
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         get car_url(car1), headers: invalid_auth_header, as: :json
#         expect(response).to have_http_status(401)
#       end
#       it "renders a 401 response" do
#         user1 = User.create! valid_create_user_1_params
#         user2 = User.create! valid_create_user_2_params
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         get car_url(car1), headers: poorly_formed_header(valid_create_user_2_params), as: :json
#         expect(response).to have_http_status(401)
#       end
#     end
#   end

#   describe "POST /create" do
#     context "without auth header" do
#       it "returns 401" do
#         user1 = User.create! valid_create_user_1_params
#         post cars_url, params: { name: "Wrenches", description: "Michael's wrenches", user_id: user1.id }
#         expect(response).to have_http_status(401)
#       end
#     end
#     context "with valid params (without image)" do
#       it "creates car" do
#         user1 = User.create! valid_create_user_1_params
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         post cars_url, headers: header, params: { name: "Wrenches", description: "Michael's wrenches", user_id: user1.id }
#         expect(response).to have_http_status(201)
#         expect(JSON.parse(response.body)).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)['name']).to eq("Wrenches")
#         expect(JSON.parse(response.body)['description']).to eq("Michael's wrenches")
#         expect(JSON.parse(response.body)['image']).to be_nil
#         expect(JSON.parse(response.body)['userId']).to eq(user1.id)
#       end
#     end
#     context "with valid params (with image)" do
#       it "creates car" do
#         user1 = User.create! valid_create_user_1_params
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         image = Rack::Test::UploadedFile.new(Rails.root.join("app/assets/images/cars/allen-wrenches.jpg"))
#         post cars_url, headers: header, params: { name: "Wrenches", description: "Michael's wrenches", image: image, user_id: user1.id }
#         expect(response).to have_http_status(201)
#         expect(JSON.parse(response.body)).to include("id","name","description","image","userId")
#         expect(JSON.parse(response.body)['name']).to eq("Wrenches")
#         expect(JSON.parse(response.body)['description']).to eq("Michael's wrenches")
#         expect(JSON.parse(response.body)['image']).to match(/http.*\/allen-wrenches\.jpg/)
#         expect(JSON.parse(response.body)['userId']).to eq(user1.id)
#       end
#       it "creates car" do
#         user1 = User.create! valid_create_user_1_params
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         image = Rack::Test::UploadedFile.new(Rails.root.join("app/assets/images/cars/allen-wrenches.jpg"))
#         expect { post cars_url, headers: header, params: { name: "Wrenches", description: "Michael's wrenches", image: image, user_id: user1.id } }
#           .to change(Car, :count).by(1)
#       end
#     end
#     context "with invalid parameters (missing user id)" do
#       it "does not create a new User" do
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         expect { post cars_url, headers: header, params: { name: "Wrenches", description: "Michael's wrenches" }, as: :json}
#           .to change(User, :count).by(0)
#       end
#       it "renders a JSON error response" do
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         post cars_url, headers: header, params: { name: "Wrenches", description: "Michael's wrenches" }, as: :json
#         expect(response).to have_http_status(:unprocessable_entity)
#         expect(response.content_type).to match(a_string_including("application/json"))
#       end
#     end
#   end

#   describe "PATCH /update" do
#     context "with valid parameters" do
#       it "updates the requested car's name" do
#         user1 = User.create! valid_create_user_1_params
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!        
#         patch car_url(car1), params: { name: "Updated Name!!"}, headers: header, as: :json
#         car1.reload
#         expect(JSON.parse(response.body)['name']).to eq "Updated Name!!"
#         expect(response).to have_http_status(:ok)
#         expect(response.content_type).to match(a_string_including("application/json"))
#       end
#       it "updates the requested cars's image" do
#         user1 = User.create! valid_create_user_1_params   
#         user2 = User.create! valid_create_user_2_params
#         header = header_from_user(user2,valid_user_2_login_params)
#         car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#         car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#         car1.save!
#         updated_image = Rack::Test::UploadedFile.new(Rails.root.join('spec/fixtures/files/images/office-avatars/erin-hannon.png'))
#         patch car_url(car1), params: { name: "test", image: updated_image }, headers: header
#         expect(response).to have_http_status(:ok)
#         expect(response.content_type).to match(a_string_including("application/json"))
#         expect(JSON.parse(response.body)['name']).to eq("test")
#         expect(JSON.parse(response.body)['image']).to be_kind_of(String)
#         expect(JSON.parse(response.body)['image']).to match(/http.*\/erin-hannon\.png/)
#       end
#     end
#   end

#   describe "DELETE /destroy" do
#     it "destroys the requested car (without avatar)" do
#       user1 = User.create! valid_create_user_1_params
#       user2 = User.create! valid_create_user_2_params      
#       header = header_from_user(user2,valid_user_2_login_params)
#       car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#       expect {
#         delete car_url(car1), headers: header, as: :json
#       }.to change(Car, :count).by(-1)
#     end
#     it "destroys the requested car (with avatar)" do
#       file = Rack::Test::UploadedFile.new(Rails.root.join("spec/fixtures/files/images/office-avatars/michael-scott.png"))
#       valid_create_user_1_params['avatar'] = file
#       user1 = User.create! valid_create_user_1_params
#       user2 = User.create! valid_create_user_2_params
#       header = header_from_user(user2,valid_user_2_login_params)
#       car1 = Car.create(name: "Wrenches", description: "Michael's wrenches", user_id: user1.id)
#       car1.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
#       car1.save!
#       expect {
#         delete car_url(car1), headers: header, as: :json
#       }.to change(Car, :count).by(-1)
#     end
#   end
# end

# private 

# def token_from_user(user,login_params)
#   post "/login", params: login_params
#   token = JSON.parse(response.body)['data']
# end

# def valid_token(create_user_params)
#   user = User.create(create_user_params)
#   post "/login", params: valid_user_1_login_params
#   token = JSON.parse(response.body)['data']
# end

# def valid_auth_header_from_token(token)
#   auth_value = "Bearer " + token
#   { Authorization: auth_value }
# end

# def valid_auth_header_from_user_params(create_user_params)
#   token = valid_token(create_user_params)
#   auth_value = "Bearer " + token
#   { Authorization: auth_value }
# end

# def header_from_user(user,login_params)
#   token = token_from_user(user,login_params)
#   auth_value = "Bearer " + token
#   { Authorization: auth_value }
# end

# def invalid_auth_header
#   auth_value = "Bearer " + "xyz"
#   { Authorization: auth_value }
# end

# def poorly_formed_header(create_user_params)
#   token = valid_token(create_user_params)
#   auth_value = "Bears " + token
#   { Authorization: auth_value }
# end

# def blob_for(name)
#   ActiveStorage::Blob.create_and_upload!(
#     io: File.open(Rails.root.join(file_fixture(name)), 'rb'),
#     filename: name,
#     content_type: 'image/png' # Or figure it out from `name` if you have non-JPEGs
#   )
# end
# ~
# EOF


# echo -e "\n\n🦄  Routes\n\n"
# cat <<'EOF' | puravida config/routes.rb ~
# Rails.application.routes.draw do
#   resources :users
#   resources :cars
#   resources :documents
#   get "health", to: "health#index"
#   post "login", to: "authentications#create"
#   get "me", to: "application#user_from_token"
# end
# ~
# EOF

# echo -e "\n\n🦄  Seeds\n\n"
# cat <<'EOF' | puravida db/seeds.rb ~
# user = User.create(name: "Michael Scott", email: "michaelscott@dundermifflin.com", admin: "true", password: "password")
# user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/michael-scott.png"), filename: "michael-scott.png")
# user.save!
# user = User.create(name: "Jim Halpert", email: "jimhalpert@dundermifflin.com", admin: "false", password: "password")
# user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/jim-halpert.png"), filename: "jim-halpert.png")
# user.save!
# user = User.create(name: "Pam Beesly", email: "pambeesly@dundermifflin.com", admin: "false", password: "password")
# user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/pam-beesly.png"), filename: "jim-halpert.png")
# user.save!
# car = Car.create(name: "Wrenches", description: "Michael's wrench", user_id: 1)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/allen-wrenches.jpg"), filename: "allen-wrenches.jpg")
# car.save!
# car = Car.create(name: "Bolts", description: "Michael's bolt", user_id: 1)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/bolts.jpg"), filename: "bolts.jpg")
# car.save!
# car = Car.create(name: "Brackets", description: "Jim's bracket", user_id: 2)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/brackets.png"), filename: "brackets.png")
# car.save!
# car = Car.create(name: "Nuts", description: "Jim's nut", user_id: 2)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/nuts.jpg"), filename: "nuts.jpg")
# car.save!
# car = Car.create(name: "Pipes", description: "Jim's pipe", user_id: 2)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/pipes.jpg"), filename: "pipes.jpg")
# car.save!
# car = Car.create(name: "Screws", description: "Pam's screw", user_id: 3)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/screws.jpg"), filename: "screws.jpg")
# car.save!
# car = Car.create(name: "Washers", description: "Pam's washer", user_id: 3)
# car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/washers.jpg"), filename: "washers.jpg")
# car.save!
# document = Document.create(name: "Sub-Button", description: "Michael's wrench's button", car_id: 1)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/button.jpg"), filename: "button.jpg")
# document.save!
# document = Document.create(name: "Sub-Buzzer", description: "Michael's bolt's buzzer", car_id: 2)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/buzzer.jpg"), filename: "buzzer.jpg")
# document.save!
# document = Document.create(name: "Sub-Capacitor", description: "Jim's bracket's capacitor", car_id: 3)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/capacitor.jpg"), filename: "capacitor.jpg")
# document.save!
# document = Document.create(name: "Sub-Dipswitch", description: "Jim's nut's dipswitch", car_id: 4)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/dip.jpg"), filename: "dip.jpg")
# document.save!
# document = Document.create(name: "Sub-Led", description: "Jim's pipe's led", car_id: 5)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/led.jpg"), filename: "led.jpg")
# document.save!
# document = Document.create(name: "Sub-Relay", description: "Pam's screw's relay", car_id: 6)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/relay.png"), filename: "relay.png")
# document.save!
# document = Document.create(name: "Sub-Resistor", description: "Pam's washer's resistor", car_id: 7)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/resistor.jpg"), filename: "resistor.jpg")
# document.save!
# document = Document.create(name: "Sub-Semiconductor", description: "Pam's washer's semiconductor", car_id: 7)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/semiconductor.jpg"), filename: "semiconductor.jpg")
# document.save!
# document = Document.create(name: "Sub-Toggle", description: "Michel's wrench's toggle", car_id: 1)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/toggle.jpg"), filename: "toggle.jpg")
# document.save!
# document = Document.create(name: "Sub-Tube", description: "Jim's bracket's tube", car_id: 3)
# document.image.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/tube.jpg"), filename: "tube.jpg")
# document.save!
# ~
# EOF
# rails db:seed

# rm -rf spec/factories
# rm -rf spec/models
# rm -rf spec/routing




# echo -e "\n\n🦄 FRONTEND\n\n"

# echo -e "\n\n🦄 Setup\n\n"

# cd ~/Desktop
# npx create-nuxt-app front
# cd front
# npm install @picocss/pico @nuxtjs/auth@4.5.1 @fortawesome/fontawesome-svg-core @fortawesome/free-solid-svg-icons @fortawesome/free-brands-svg-icons @fortawesome/vue-fontawesome@latest-2
# npm install --save-dev sass sass-loader@10
# cat <<'EOF' | puravida assets/scss/main.scss ~
# @import "node_modules/@picocss/pico/scss/pico.scss";

# // Pico overrides 
# // $primary-500: #e91e63;

# h1 {
#   margin: 4rem 0
# }

# .no-margin {
#   margin: 0
# }

# .small-bottom-margin {
#   margin: 0 0 0.5rem
# }

# .big-bottom-margin {
#   margin: 0 0 8rem
# }

# .half-width {
#   margin: 0 0 4rem;
#   width: 50%;
# }

# nav img {
#   width: 40px;
#   border-radius: 50%;
#   border: 3px solid var(--primary);
# }

# article img {
#   margin-bottom: var(--typography-spacing-vertical);
#   width: 250px;
# }

# ul.features { 
#   margin: 0 0 2.5rem 1rem;
#   li {
#     margin: 0;
#     padding: 0;
#   }
# }

# .aligned-columns {
#   margin: 0 0 2rem;
#   p {
#     margin: 0;
#     span {
#       margin: 0 0.5rem 0 0;
#       display: inline-block;
#       width: 8rem;
#       text-align: right;
#       font-weight: bold;
#     }
#   }
# }
# ~
# EOF
# cat <<'EOF' | puravida nuxt.config.js ~
# let development = process.env.NODE_ENV !== 'production'
# export default {
#   ssr: false,
#   head: { title: 'front', htmlAttrs: { lang: 'en' },
#     meta: [ { charset: 'utf-8' },
#       { name: 'viewport', content: 'width=device-width, initial-scale=1' },
#       { hid: 'description', name: 'description', content: '' },
#       { name: 'format-detection', content: 'telephone=no' }
#     ], link: [{ rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }]
#   },
#   css: ['@fortawesome/fontawesome-svg-core/styles.css','@/assets/scss/main.scss'],
#   plugins: [ '~/plugins/fontawesome.js' ],
#   components: true,
#   buildModules: [],
#   router: { middleware: ['auth'] },
#   modules: ['@nuxtjs/axios', '@nuxtjs/auth'],
#   axios: { baseURL: development ? 'http://localhost:3000' : 'https://ruxtmin-back.fly.dev/' },
#   server: { port: development ? 3001 : 3000 },
#   auth: {
#     redirect: { login: '/' },
#     strategies: {
#       local: {
#         endpoints: {
#           login: { url: 'login', method: 'post', propertyName: 'data' },
#           logout: false,
#           user: { url: 'me', method: 'get', propertyName: 'data' }
#         }
#       }
#     }
#   }
# }
# ~
# EOF
# cat <<'EOF' | puravida middleware/adminOnly.js ~
# export default function ({ store, redirect }) {
#   if (!store.state.auth.user.admin) {
#     return redirect('/')
#   }
# }
# ~
# EOF
# cat <<'EOF' | puravida middleware/currentOrAdmin-showEdit.js ~
# import { mapGetters } from 'vuex'
# export default function ({ route, store, redirect }) {
#   const { isAdmin, loggedInUser } = store.getters
#   const url = route.fullPath;
#   const splitPath = url.split('/')
#   let elemId = null
#   let isElemUsers = false
#   let isCar = false;
#   let isDocument = false;
#   let isUser = false;
#   const userCars = loggedInUser.car_ids
#   const userDocuments = loggedInUser.document_ids

#   if (url.includes("document")) {
#     isDocument = true
#   } else if (url.includes("car")) {
#     isCar = true
#   } else if (url.includes("users")) {
#     isUser = true
#   }

#   if (isEditPage(url)) {
#     elemId = parseInt(splitPath[splitPath.length-2])
#   } else if (isShowPage(url)) {
#     elemId = parseInt(splitPath[splitPath.length-1])
#   }
  
#   if (isCar) {
#     isElemUsers = userCars.includes(elemId) ? true : false
#   } else if (isDocument) {
#     isElemUsers = userDocuments.includes(elemId) ? true : false
#   } else if (isUser) {
#     isElemUsers = loggedInUser.id === elemId ? true : false
#   }

#   if (!isAdmin && !isElemUsers) {
#     return redirect('/')
#   }
# }

# function isEditPage(url) {
#   return url.includes("edit") ? true : false
# }

# function isShowPage(url) {
#   const splitUrl = url.split('/')
#   return (!isNaN(splitUrl[splitUrl.length-1]) && !isEditPage(url)) ? true : false
# }
# ~
# EOF
# cat <<'EOF' | puravida middleware/currentOrAdmin-index.js ~
# export default function ({ route, store, redirect }) {
#   const { isAdmin, loggedInUser } = store.getters
#   const query = route.query
#   const isAdminRequest = query['admin'] ? true : false
#   const isUserIdRequest = query['user_id'] ? true : false
#   const isQueryEmpty = Object.keys(query).length === 0 ? true : false
#   const userIdRequestButNotAdmin = isUserIdRequest && !isAdmin
#   const requested_user_id = parseInt(query['user_id'])
#   const actual_user_id = loggedInUser.id
#   const allowedAccess = requested_user_id === actual_user_id ? true : false

#   if ((isAdminRequest || isQueryEmpty) && !isAdmin) {
#     return redirect('/')
#   } else if (userIdRequestButNotAdmin && !allowedAccess) {
#     return redirect('/cars?user_id=' + loggedInUser.id)
#   }
# }
# ~
# EOF
# cat <<'EOF' | puravida plugins/fontawesome.js ~
# import Vue from 'vue'
# import { library, config } from '@fortawesome/fontawesome-svg-core'
# import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
# import { fas } from '@fortawesome/free-solid-svg-icons'

# config.autoAddCss = false
# library.add(fas)
# Vue.component('font-awesome-icon', FontAwesomeIcon)
# ~
# EOF
# rm -f components/*.vue
# echo -e "\n\n🦄 New User Page\n\n"
# cat <<'EOF' | puravida components/user/Form.vue ~
# <template>
#   <section>
#     <h1 v-if="editNewOrSignup === 'edit'">Edit User</h1>
#     <h1 v-else-if="editNewOrSignup === 'new'">Add User</h1>
#     <h1 v-else-if="editNewOrSignup === 'sign-up'">Sign Up</h1>
#     <article>
#       <form enctype="multipart/form-data">
#         <p v-if="editNewOrSignup === 'edit'">id: {{ $route.params.id }}</p>
#         <p>Name: </p><input v-model="name">
#         <p>Email: </p><input v-model="email">
#         <p class="no-margin">Avatar: </p>
#         <img v-if="!hideAvatar && editNewOrSignup === 'edit'" :src="avatar" />    
#         <input type="file" ref="inputFile" @change=uploadAvatar()>
#         <p v-if="editNewOrSignup !== 'edit'">Password: </p>
#         <input v-if="editNewOrSignup !== 'edit'" type="password" v-model="password">
#         <button v-if="editNewOrSignup !== 'edit'" @click.prevent=createUser>Create User</button>
#         <button v-else-if="editNewOrSignup == 'edit'" @click.prevent=editUser>Edit User</button>
#       </form>
#     </article>
#   </section>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   data () {
#     return {
#       name: "",
#       email: "",
#       avatar: "",
#       password: "",
#       editNewOrSignup: "",
#       hideAvatar: false
#     }
#   },
#   mounted() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editNewOrSignup = splitPath[splitPath.length-1]
#   },
#   computed: {
#     ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
#   },
#   async fetch() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editNewOrSignup = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
#     if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
#       const user = await this.$axios.$get(`users/${this.$route.params.id}`)
#       this.name = user.name
#       this.email = user.email,
#       this.avatar = user.avatar  
#     }
#   },
#   methods: {
#     uploadAvatar: function() {
#       this.avatar = this.$refs.inputFile.files[0]
#       this.hideAvatar = true
#     },
#     createUser: function() {
#       const params = {
#         'name': this.name,
#         'email': this.email,
#         'avatar': this.avatar,
#         'password': this.password,
#       }
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$post('users', payload)
#         .then(() => {
#           this.$auth.loginWith('local', {
#             data: {
#             email: this.email,
#             password: this.password
#             },
#           })
#           .then(() => {
#             const userId = this.$auth.$state.user.id
#             this.$router.push(`/users/${userId}`)
#           })
#         })
#     },
#     editUser: function() {
#       let params = {}
#       const filePickerFile = this.$refs.inputFile.files[0]
#       if (!filePickerFile) {
#         params = { 'name': this.name, 'email': this.email }
#       } else {
#         params = { 'name': this.name, 'email': this.email, 'avatar': this.avatar }
#       }
    
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$patch(`/users/${this.$route.params.id}`, payload)
#         .then(() => {
#           this.$router.push(`/users/${this.$route.params.id}`)
#         })
#     },
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida pages/users/new.vue ~
# <template>
#   <main class="container">
#     <UserForm />
#   </main>
# </template>
# ~
# EOF
# echo -e "\n\n🦄 Users Page\n\n"
# cat <<'EOF' | puravida components/user/Card.vue ~
# <template>
#   <article>
#     <h2>
#       <NuxtLink :to="`/users/${user.id}`">{{ user.name }}</NuxtLink> 
#       <NuxtLink :to="`/users/${user.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
#       <a @click.prevent=deleteUser(user.id) href="#"><font-awesome-icon icon="trash" /></a>
#     </h2>
#     <p>id: {{ user.id }}</p>
#     <p>email: {{ user.email }}</p>
#     <p v-if="user.avatar !== null" class="no-margin">avatar:</p>
#     <img v-if="user.avatar !== null" :src="user.avatar" />
#     <p v-if="isAdmin">admin: {{ user.admin }}</p>
#   </article>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   name: 'UserCard',
#   computed: { ...mapGetters(['isAdmin']) },
#   props: {
#     user: {
#       type: Object,
#       default: () => ({}),
#     },
#     users: {
#       type: Array,
#       default: () => ([]),
#     },
#   },
#   methods: {
#     uploadAvatar: function() {
#       this.avatar = this.$refs.inputFile.files[0];
#     },
#     deleteUser: function(id) {
#       this.$axios.$delete(`users/${id}`)
#       const index = this.users.findIndex((i) => { return i.id === id })
#       this.users.splice(index, 1);
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida components/user/Set.vue ~
# <template>
#   <section>
#     <div v-for="user in users" :key="user.id">
#       <UserCard :user="user" :users="users" />
#     </div>
#   </section>
# </template>

# <script>
# export default {
#   data: () => ({
#     users: []
#   }),
#   async fetch() {
#     this.users = await this.$axios.$get('users')
#   }
# }
# </script>
# ~
# EOF

# cat <<'EOF' | puravida pages/users/index.vue ~
# <template>
#   <main class="container">
#     <h1>Users</h1>
#     <NuxtLink to="/users/new" role="button">Add User</NuxtLink>
#     <UserSet />
#   </main>
# </template>

# <script>
# export default { middleware: 'adminOnly' }
# </script>
# ~
# EOF

# echo -e "\n\n🦄 User Page\n\n"
# cat <<'EOF' | puravida pages/users/_id/index.vue ~
# <template>
#   <main class="container">
#     <section>
#       <UserCard :user="user" />
#     </section>
#   </main>
# </template>

# <script>
# export default {
#   middleware: 'currentOrAdmin-showEdit',
#   data: () => ({ user: {} }),
#   async fetch() { this.user = await this.$axios.$get(`users/${this.$route.params.id}`) },
#   methods: {
#     uploadAvatar: function() { this.avatar = this.$refs.inputFile.files[0] },
#     deleteUser: function(id) {
#       this.$axios.$delete(`users/${this.$route.params.id}`)
#       this.$router.push('/users')
#     }
#   }
# }
# </script>
# ~
# EOF

# echo -e "\n\n🦄 User Edit Page\n\n"
# cat <<'EOF' | puravida pages/users/_id/edit.vue ~
# <template>
#   <main class="container">
#     <UserForm />
#   </main>
# </template>

# <script>
# export default { middleware: 'currentOrAdmin-showEdit' }
# </script>
# ~
# EOF


# echo -e "\n\n🦄 Cars (frontend)\n\n"
# cat <<'EOF' | puravida components/car/Card.vue ~
# <template>
#   <article>
#     <h2>
#       <NuxtLink :to="`/cars/${car.id}`">{{ car.name }}</NuxtLink> 
#       <NuxtLink :to="`/cars/${car.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
#       <a @click.prevent=deleteCar(car.id) href="#"><font-awesome-icon icon="trash" /></a>
#     </h2>
#     <p>id: {{ car.id }}</p>
#     <p>description: {{ car.description }}</p>
#     <p v-if="car.image !== null" class="no-margin">image:</p>
#     <img v-if="car.image !== null" :src="car.image" />
#     <h4 v-if="car.documents !== null">Documents</h4>
#     <ul v-if="car.documents !== null">
#       <li v-for="document in car.documents" :key="document.id">
#         <NuxtLink :to="`/documents/${document.id}`">{{ document.name }} - {{ document.description }}</NuxtLink>
#       </li>
#     </ul>
#   </article>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   name: 'CarCard',
#   computed: { ...mapGetters(['isAdmin']) },
#   props: {
#     car: {
#       type: Object,
#       default: () => ({}),
#     },
#     cars: {
#       type: Array,
#       default: () => ([]),
#     },
#   },
#   methods: {
#     uploadImage: function() {
#       this.image = this.$refs.inputFile.files[0];
#     },
#     deleteCar: function(id) {
#       this.$axios.$delete(`cars/${id}`)
#       const index = this.cars.findIndex((i) => { return i.id === id })
#       this.cars.splice(index, 1);
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida components/car/Set.vue ~
# <template>
#   <section>
#     <div v-for="car in cars" :key="car.id">
#       <CarCard :car="car" :cars="cars" />
#     </div>
#   </section>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
#   data: () => ({
#     cars: []
#   }),
#   async fetch() {
#     const query = this.$store.$auth.ctx.query
#     const adminQuery = query.admin
#     const idQuery = query.user_id
    
#     if (this.isAdmin && adminQuery) {
#       this.cars = await this.$axios.$get('cars')
#     } else if (idQuery) {
#       this.cars = await this.$axios.$get('cars', {
#         params: { user_id: idQuery }
#       })
#     } else {
#       this.cars = await this.$axios.$get('cars', {
#         params: { user_id: this.loggedInUser.id }
#       })
#     }
#   }
# }
# </script>
# ~
# EOF

# cat <<'EOF' | puravida components/car/Form.vue ~
# <template>
#   <section>
#     <h1 v-if="editOrNew === 'edit'">Edit Car</h1>
#     <h1 v-else-if="editOrNew === 'new'">Add Car</h1>
#     <article>
#       <form enctype="multipart/form-data">
#         <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
#         <p>Name: </p><input v-model="name">
#         <p>Description: </p><input v-model="description">
#         <p class="no-margin">Image: </p>
#         <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
#         <input type="file" ref="inputFile" @change=uploadImage()>
#         <button v-if="editOrNew !== 'edit'" @click.prevent=createCar>Create Car</button>
#         <button v-else-if="editOrNew == 'edit'" @click.prevent=editCar>Edit Car</button>
#       </form>
#     </article>
#   </section>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   data () {
#     return {
#       name: "",
#       description: "",
#       image: "",
#       editOrNew: "",
#       hideImage: false
#     }
#   },
#   mounted() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editOrNew = splitPath[splitPath.length-1]
#   },
#   computed: {
#     ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
#   },
#   async fetch() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
#     if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
#       const car = await this.$axios.$get(`cars/${this.$route.params.id}`)
#       this.name = car.name
#       this.description = car.description,
#       this.image = car.image  
#     }
#   },
#   methods: {
#     uploadImage: function() {
#       this.image = this.$refs.inputFile.files[0]
#       this.hideImage = true
#     },
#     createCar: function() {
#       const userId = this.$auth.$state.user.id
#       const params = {
#         'name': this.name,
#         'description': this.description,
#         'image': this.image,
#         'user_id': userId
#       }
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$post('cars', payload)
#         .then((res) => {
#           const carId = res.id
#           this.$router.push(`/cars/${carId}`)
#         })
#     },
#     editCar: function() {
#       let params = {}
#       const filePickerFile = this.$refs.inputFile.files[0]
#       if (!filePickerFile) {
#         params = { 'name': this.name, 'description': this.description }
#       } else {
#         params = { 'name': this.name, 'description': this.description, 'image': this.image }
#       }
    
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$patch(`/cars/${this.$route.params.id}`, payload)
#         .then(() => {
#           this.$router.push(`/cars/${this.$route.params.id}`)
#         })
#     },
#   }
# }
# </script>
# ~
# EOF


# cat <<'EOF' | puravida pages/cars/index.vue ~
# <template>
#   <main class="container">
#     <h1>Cars</h1>
#     <NuxtLink to="/cars/new" role="button">Add Car</NuxtLink>
#     <CarSet />
#   </main>
# </template>
# <script>
# export default { middleware: 'currentOrAdmin-index' }
# </script>
# ~
# EOF

# cat <<'EOF' | puravida pages/cars/new.vue ~
# <template>
#   <main class="container">
#     <CarForm />
#   </main>
# </template>
# ~
# EOF

# cat <<'EOF' | puravida pages/cars/_id/index.vue ~
# <template>
#   <main class="container">
#     <section>
#       <CarCard :car="car" />
#     </section>
#   </main>
# </template>

# <script>
# export default {
#   middleware: 'currentOrAdmin-showEdit',
#   data: () => ({ car: {} }),
#   async fetch() { this.car = await this.$axios.$get(`cars/${this.$route.params.id}`) },
#   methods: {
#     uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
#     deleteCar: function(id) {
#       this.$axios.$delete(`cars/${this.$route.params.id}`)
#       this.$router.push('/cars')
#     }
#   }
# }
# </script>
# ~
# EOF

# cat <<'EOF' | puravida pages/cars/_id/edit.vue ~
# <template>
#   <main class="container">
#     <CarForm />
#   </main>
# </template>

# <script>
# export default { middleware: 'currentOrAdmin-showEdit' }
# </script>
# ~
# EOF

# echo -e "\n\n🦄 Documents (frontend)\n\n"
# cat <<'EOF' | puravida components/document/Card.vue ~
# <template>
#   <article>
#     <h2>
#       <NuxtLink :to="`/documents/${document.id}`">{{ document.name }}</NuxtLink> 
#       <NuxtLink :to="`/documents/${document.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
#       <a @click.prevent=deleteCar(document.id) href="#"><font-awesome-icon icon="trash" /></a>
#     </h2>
#     <p>id: {{ document.id }}</p>
#     <p>description: {{ document.description }}</p>
#     <p v-if="document.image !== null" class="no-margin">image:</p>
#     <img v-if="document.image !== null" :src="document.image" />
#     <p>car: <NuxtLink :to="`/cars/${document.carId}`">{{ document.carName }} - {{ document.carDescription }}</NuxtLink></p>
#   </article>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   name: 'DocumentCard',
#   computed: { ...mapGetters(['isAdmin']) },
#   props: {
#     document: {
#       type: Object,
#       default: () => ({}),
#     },
#     documents: {
#       type: Array,
#       default: () => ([]),
#     },
#   },
#   methods: {
#     uploadImage: function() {
#       this.image = this.$refs.inputFile.files[0];
#     },
#     deleteDocument: function(id) {
#       this.$axios.$delete(`documents/${id}`)
#       const index = this.documents.findIndex((i) => { return i.id === id })
#       this.documents.splice(index, 1);
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida components/document/Set.vue ~
# <template>
#   <section>
#     <div v-for="document in documents" :key="document.id">
#       <DocumentCard :document="document" :documents= "documents" />
#     </div>
#   </section>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
#   data: () => ({
#     documents: []
#   }),
#   async fetch() {
#     const query = this.$store.$auth.ctx.query
#     const adminQuery = query.admin
#     const idQuery = query.user_id
    
#     if (this.isAdmin && adminQuery) {
#       this.documents = await this.$axios.$get('documents')
#     } else if (idQuery) {
#       this.documents = await this.$axios.$get('documents', {
#         params: { user_id: idQuery }
#       })
#     } else {
#       this.documents = await this.$axios.$get('documents', {
#         params: { user_id: this.loggedInUser.id }
#       })
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida components/document/Form.vue ~
# <template>
#   <section>
#     <h1 v-if="editOrNew === 'edit'">Edit Document</h1>
#     <h1 v-else-if="editOrNew === 'new'">Add Document</h1>
#     <article>
#       <form enctype="multipart/form-data">
#         <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
#         <p>Name: </p><input v-model="name">
#         <p>Description: </p><input v-model="description">
#         <p class="no-margin">Image: </p>
#         <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
#         <input type="file" ref="inputFile" @change=uploadImage()>
#         <p>Car: </p>
#         <select v-if="editOrNew === 'new'" name="car" @change="selectCar($event)">
#           <option value=""></option>
#           <option v-for="car in cars" :key="car.id" :value="car.id">{{ car.name }} - {{ car.description }}</option>
#         </select>
#         <button v-if="editOrNew !== 'edit'" @click.prevent=createDocument>Create Document</button>
#         <button v-else-if="editOrNew == 'edit'" @click.prevent=editDocument>Edit Document</button>
#       </form>
#     </article>
#   </section>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   data () {
#     return {
#       name: "",
#       description: "",
#       image: "",
#       editOrNew: "",
#       hideImage: false,
#       cars: [],
#       carId: ""
#     }
#   },
#   mounted() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editOrNew = splitPath[splitPath.length-1]
#   },
#   computed: {
#     ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
#   },
#   async fetch() {
#     const splitPath = $nuxt.$route.path.split('/')
#     this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
#     if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
#       const document = await this.$axios.$get(`documents/${this.$route.params.id}`)
#       this.name = document.name
#       this.description = document.description,
#       this.image = document.image  
#     }
#     if (this.editOrNew == 'new') {
#       this.cars = await this.$axios.$get('/cars', {
#         params: { user_id: this.$auth.$state.user.id }
#       })
#     }
#   },
#   methods: {
#     uploadImage: function() {
#       this.image = this.$refs.inputFile.files[0]
#       this.hideImage = true
#     },
#     createDocument: function() {
#       const params = {
#         'name': this.name,
#         'description': this.description,
#         'image': this.image,
#         'car_id': this.carId
#       }
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$post('documents', payload)
#         .then((res) => {
#           const documentId = res.id
#           this.$router.push(`/documents/${documentId}`)
#         })
#     },
#     editDocument: function() {
#       let params = {}
#       const filePickerFile = this.$refs.inputFile.files[0]
#       if (!filePickerFile) {
#         params = { 'name': this.name, 'description': this.description }
#       } else {
#         params = { 'name': this.name, 'description': this.description, 'image': this.image }
#       } 
#       let payload = new FormData()
#       Object.entries(params).forEach(
#         ([key, value]) => payload.append(key, value)
#       )
#       this.$axios.$patch(`/documents/${this.$route.params.id}`, payload)
#         .then(() => {
#           this.$router.push(`/documents/${this.$route.params.id}`)
#         })
#     },
#     selectCar: function(event) {
#       this.carId = event.target.value
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida pages/documents/index.vue ~
# <template>
#   <main class="container">
#     <h1>Documents</h1>
#     <NuxtLink to="/documents/new" role="button">Add Document</NuxtLink>
#     <DocumentSet />
#   </main>
# </template>
# <script>
# export default { middleware: 'currentOrAdmin-index' }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida pages/documents/new.vue ~
# <template>
#   <main class="container">
#     <DocumentForm />
#   </main>
# </template>
# ~
# EOF
# cat <<'EOF' | puravida pages/documents/_id/index.vue ~
# <template>
#   <main class="container">
#     <section>
#       <DocumentCard :document="document" />
#     </section>
#   </main>
# </template>

# <script>
# export default {
#   middleware: 'currentOrAdmin-showEdit',
#   data: () => ({ document: {} }),
#   async fetch() { this.document = await this.$axios.$get(`documents/${this.$route.params.id}`) },
#   methods: {
#     uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
#     deleteDocument: function(id) {
#       this.$axios.$delete(`documents/${this.$route.params.id}`)
#       this.$router.push('/documents')
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida pages/documents/_id/edit.vue ~
# <template>
#   <main class="container">
#     <CarForm />
#   </main>
# </template>

# <script>
# export default { middleware: 'currentOrAdmin-showEdit' }
# </script>
# ~
# EOF

# echo -e "\n\n🦄 Nav\n\n"
# cat <<'EOF' | puravida components/nav/Brand.vue ~
# <template>
#   <span>
#     <font-awesome-icon icon="laptop-code" /> Ruxtmin
#   </span>
# </template>
# ~
# EOF
# cat <<'EOF' | puravida components/nav/Default.vue ~
# <template>
#   <nav class="top-nav container-fluid">
#     <ul><li><strong><NuxtLink to="/"><NavBrand /></NuxtLink></strong></li></ul>
#     <input id="menu-toggle" type="checkbox" />
#     <label class='menu-button-container' for="menu-toggle">
#       <div class='menu-button'></div>
#     </label>
#     <ul class="menu">
#       <li v-if="!isAuthenticated"><strong><NuxtLink to="/log-in">Log In</NuxtLink></strong></li>
#       <li v-if="!isAuthenticated"><strong><NuxtLink to="/sign-up">Sign Up</NuxtLink></strong></li>
#       <li v-if="isAuthenticated"><strong><NuxtLink :to="`/cars?user_id=${loggedInUser.id}`">Cars</NuxtLink></strong></li>
#       <li v-if="isAuthenticated"><strong><NuxtLink :to="`/documents?user_id=${loggedInUser.id}`">Documents</NuxtLink></strong></li>
#       <li v-if="isAdmin"><strong><NuxtLink to="/admin">Admin</NuxtLink></strong></li>
#       <li v-if="isAuthenticated" class='dropdown'>
#         <details role="list" dir="rtl">
#           <summary class='summary' aria-haspopup="listbox" role="link">
#             <img v-if="loggedInUser.avatar" :src="loggedInUser.avatar" />
#             <font-awesome-icon v-else icon="circle-user" />
#           </summary>
#           <ul role="listbox">
#             <li><NuxtLink :to="`/users/${loggedInUser.id}`">Profile</NuxtLink></li>
#             <li><NuxtLink :to="`/users/${loggedInUser.id}/edit`">Settings</NuxtLink></li>
#             <li><a @click="logOut">Log Out</a></li>
#           </ul>
#         </details>
#       </li>
#       <!-- <li v-if="isAuthenticated"><strong><NuxtLink :to="`/users/${loggedInUser.id}`">Settings</NuxtLink></strong></li> -->
#       <li class="logout-desktop" v-if="isAuthenticated"><strong><a @click="logOut">Log Out</a></strong></li>
#     </ul>
#   </nav>
# </template>

# <script>
# import { mapGetters } from 'vuex'
# export default {
#   computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
#   methods: { logOut() { this.$auth.logout() } }
# }
# </script>

# <style lang="sass" scoped>
# // css-only responsive nav
# // from https://codepen.io/alvarotrigo/pen/MWEJEWG (accessed 10/16/23, modified slightly)

# h2 
#   vertical-align: center
#   text-align: center

# html, body 
#   margin: 0
#   height: 100%

# .top-nav 
#   height: 50px

# .top-nav > ul 
#   margin-top: 15px

# .menu 
#   display: flex
#   flex-direction: row
#   list-style-type: none
#   margin: 0
#   padding: 0

# [type="checkbox"] ~ label.menu-button-container 
#   display: none
#   height: 100%
#   width: 30px
#   cursor: pointer
#   flex-direction: column
#   justify-content: center
#   align-items: center

# #menu-toggle 
#   display: none

# .menu-button,
# .menu-button::before,
# .menu-button::after 
#   display: block
#   background-color: #000
#   position: absolute
#   height: 4px
#   width: 30px
#   transition: transform 400ms cubic-bezier(0.23, 1, 0.32, 1)
#   border-radius: 2px

# .menu-button::before 
#   content: ''
#   margin-top: -8px

# .menu-button::after 
#   content: ''
#   margin-top: 8px

# #menu-toggle:checked + .menu-button-container .menu-button::before 
#   margin-top: 0px
#   transform: rotate(405deg)

# #menu-toggle:checked + .menu-button-container .menu-button 
#   background: rgba(255, 255, 255, 0)

# #menu-toggle:checked + .menu-button-container .menu-button::after 
#   margin-top: 0px
#   transform: rotate(-405deg)

# .menu 
#   > li 
#     overflow: visible

#   > li.dropdown
#     background: none

#     .summary
#       margin: 0
#       padding: 1rem 0
#       font-size: 1.5rem

#       &:focus
#         color: var(--color)
#         background: none

#       &:after
#         display: none

#     ul
#       padding-top: 0
#       margin-top: 0
#       right: -1rem

#   > li.logout-desktop
#     display: none

# @media (max-width: 991px) 
#   .menu 
    
#     > li 
#       overflow: hidden
    
#     > li.dropdown
#       display: none

#     > li.logout-desktop
#       display: flex

#   [type="checkbox"] ~ label.menu-button-container 
#     display: flex

#   .top-nav > ul.menu 
#     position: absolute
#     top: 0
#     margin-top: 50px
#     left: 0
#     flex-direction: column
#     width: 100%
#     justify-content: center
#     align-items: center

#   #menu-toggle ~ .menu li 
#     height: 0
#     margin: 0
#     padding: 0
#     border: 0
#     transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1)

#   #menu-toggle:checked ~ .menu li 
#     border: 1px solid #333
#     height: 2.5em
#     padding: 0.5em
#     transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1)

#   .menu > li 
#     display: flex
#     justify-content: center
#     margin: 0
#     padding: 0.5em 0
#     width: 100%
#     // color: white
#     background-color: #222

#   .menu > li:not(:last-child) 
#     border-bottom: 1px solid #444
# </style>
# ~
# EOF
# cat <<'EOF' | puravida layouts/default.vue ~
# <template>
#   <div>
#     <NavDefault />
#     <Nuxt />
#   </div>
# </template>
# ~
# EOF
# echo -e "\n\n🦄 Home\n\n"
# cat <<'EOF' | puravida pages/index.vue ~
# <template>
#   <main class="container">
#     <h1>Rails 7 Nuxt 2 Admin Boilerplate</h1>
    
#     <h2 class="small-bottom-margin">Features</h2>
#     <ul class="features">
#       <li>Admin dashboard</li>
#       <li>Placeholder users</li>
#       <li>Placeholder user item ("car")</li>
#     </ul>

#     <h3 class="small-bottom-margin stack">Stack</h3>
#     <div class="aligned-columns">
#       <p><span>frontend:</span> Nuxt 2</p>
#       <p><span>backend API:</span> Rails 7</p>
#       <p><span>database:</span> Postgres</p>
#       <p><span>styles:</span> Sass</p>
#       <p><span>css framework:</span> Pico.css</p>
#       <p><span>e2e tests:</span> Cypress</p>
#       <p><span>api tests:</span> RSpec</p>
#     </div>

#     <h3 class="small-bottom-margin tools">Tools</h3>
#     <div class="aligned-columns">
#       <p><span>user avatars:</span> local active storage</p>
#       <p><span>backend auth:</span> bcrypt & jwt</p>
#       <p><span>frontend auth:</span> nuxt auth module</p>
#     </div>

#     <h3 class="small-bottom-margin">User Logins</h3>
#     <table class="half-width">
#       <tr><th>Email</th><th>Password</th><th>Notes</th></tr>
#       <tr><td>michaelscott@dundermifflin.com</td><td>password</td><td>(admin)</td></tr>
#       <tr><td>jimhalpert@dundermifflin.com</td><td>password</td><td></td></tr>
#       <tr><td>pambeesly@dundermifflin.com</td><td>password</td><td></td></tr>
#     </table>
    
#     <p class="big-bottom-margin">
#       <NuxtLink to="/log-in" role="button" class="secondary">Log In</NuxtLink> 
#       <NuxtLink to="/sign-up" role="button" class="contrast outline">Sign Up</NuxtLink>
#     </p>    

#   </main>
# </template>

# <script>
# export default { auth: false }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida components/Notification.vue ~
# <template>
#   <div class="notification is-danger">
#     {{ message }}
#   </div>
# </template>

# <script>
# export default {
#   name: 'Notification',
#   props: ['message']
# }
# </script>
# ~
# EOF

# echo -e "\n\n🦄 Login & Signup Pages\n\n"
# cat <<'EOF' | puravida pages/log-in.vue ~
# <template>
#   <main class="container">
#     <h2>Log In</h2>
#     <Notification :message="error" v-if="error"/>
#     <form method="post" @submit.prevent="login">
#       <div>
#         <label>Email</label>
#         <div>
#           <input
#             type="email"
#             name="email"
#             v-model="email"
#           />
#         </div>
#       </div>
#       <div>
#         <label>Password</label>
#         <div>
#           <input
#             type="password"
#             name="password"
#             v-model="password"
#           />
#         </div>
#       </div>
#       <div>
#         <button type="submit">Log In</button>
#       </div>
#     </form>
#     <div>
#       <p>
#         Don't have an account? <NuxtLink to="/sign-up">Sign up</NuxtLink>
#       </p>
#     </div>
#   </main>
# </template>

# <script>
# import Notification from '~/components/Notification'
# export default {
#   auth: false,
#   components: {
#     Notification,
#   },
#   data() {
#     return {
#       email: '',
#       password: '',
#       error: null
#     }
#   },
#   methods: {
#     async login() {
#       this.$auth.loginWith('local', {
#         data: {
#           email: this.email,
#           password: this.password
#         }
#       }).then (() => {
#         const id = this.$auth.$state.user.id
#         this.$router.push(`/users/${id}`)
#       })
#     }
#   }
# }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida pages/sign-up.vue ~
# <template>
#   <main class="container">
#     <UserForm />      
#   </main>
# </template>

# <script>
# export default { auth: false }
# </script>
# ~
# EOF
# cat <<'EOF' | puravida store/index.js ~
# export const getters = {
#   isAuthenticated(state) {
#     return state.auth.loggedIn
#   },

#   isAdmin(state) {
#     if (state.auth.user && state.auth.user.admin !== null && state.auth.user.admin == true) { 
#         return true
#     } else {
#       return false
#     } 
#   },

#   loggedInUser(state) {
#     return state.auth.user
#   }
# }
# ~
# EOF

# echo -e "\n\n🦄 Admin Page\n\n"

# cat <<'EOF' | puravida pages/admin/index.vue ~
# <template>
#   <main class="container">
#     <h1>Admin</h1>
#     <p>Number of users: {{ this.users.length }}</p>
#     <p>Number of admins: {{ (this.users.filter((obj) => obj.admin === true)).length }}</p>
#     <p><NuxtLink to="/users">Users</NuxtLink></p>
#     <p><NuxtLink to="/cars?admin=true">Cars</NuxtLink></p>
#   </main>
# </template>

# <script>
# export default { 
#   middleware: 'adminOnly',
#   layout: 'admin',
#   data: () => ({ users: [] }),
#   async fetch() { this.users = await this.$axios.$get('users') }
# }
# </script>
# ~
# EOF


# echo -e "\n\n🦄 Cypress\n\n"
# cd ~/Desktop/front
# npm install cypress --save-dev
# npx cypress open
# puravida cypress/fixtures/images
# cp -a ~/Desktop/ruxtmin/assets/images/office-avatars ~/Desktop/front/cypress/fixtures/images

# cat <<'EOF' | puravida cypress/support/commands.js ~
# Cypress.Commands.add('login', () => { 
#   cy.visit('http://localhost:3001/log-in')
#   cy.get('input').eq(1).type('jimhalpert@dundermifflin.com')
#   cy.get('input').eq(2).type('password{enter}')
# })

# Cypress.Commands.add('loginNonAdmin', () => { 
#   cy.visit('http://localhost:3001/log-in')
#   cy.get('input').eq(1).type('jimhalpert@dundermifflin.com')
#   cy.get('input').eq(2).type('password{enter}')
# })

# Cypress.Commands.add('loginAdmin', () => { 
#   cy.visit('http://localhost:3001/log-in')
#   cy.get('input').eq(1).type('michaelscott@dundermifflin.com')
#   cy.get('input').eq(2).type('password{enter}')
# })

# Cypress.Commands.add('loginInvalid', () => { 
#   cy.visit('http://localhost:3001/log-in')
#   cy.get('input').eq(1).type('xyz@dundermifflin.com')
#   cy.get('input').eq(2).type('password{enter}')
# })

# Cypress.Commands.add('logoutNonAdmin', (admin) => { 
#   cy.logout(false);
# })

# Cypress.Commands.add('logoutAdmin', (admin) => { 
#   cy.logout(true);
# })

# Cypress.Commands.add('logout', (admin) => { 
#   const num = admin ? 3 : 2
#   cy.get('nav ul.menu').find('li').eq(num).click()
#     .then(() => { cy.get('nav details ul').find('li').eq(2).click() })
# })
# ~
# EOF
# cat <<'EOF' | puravida cypress/e2e/logged-out-page-copy.cy.js ~
# /// <reference types="cypress" />

# // reset the db: db:drop db:create db:migrate db:seed RAILS_ENV=test
# // run dev server with test db: CYPRESS=1 bin/rails server -p 3000
# context('Logged Out', () => {
#   describe('Homepage Copy', () => {
#     it('should find page copy', () => {
#       cy.visit('http://localhost:3001/')
#       cy.get('main.container')
#         .should('contain', 'Rails 7 Nuxt 2 Admin Boilerplate')
#         .should('contain', 'Features')
#       cy.get('ul.features')
#         .within(() => {
#           cy.get('li').eq(0).contains('Admin dashboard')
#           cy.get('li').eq(1).contains('Placeholder users')
#           cy.get('li').eq(2).contains('Placeholder user item ("car")')
#         })
#       cy.get('h3.stack')
#         .next('div.aligned-columns')
#           .within(() => {
#             cy.get('p').eq(0).contains('frontend:')
#             cy.get('p').eq(0).contains('Nuxt 2')
#             cy.get('p').eq(1).contains('backend API:')
#             cy.get('p').eq(1).contains('Rails 7')
#             cy.get('p').eq(2).contains('database:')
#             cy.get('p').eq(2).contains('Postgres')
#             cy.get('p').eq(3).contains('styles:')
#             cy.get('p').eq(3).contains('Sass')
#             cy.get('p').eq(4).contains('css framework:')
#             cy.get('p').eq(4).contains('Pico.css')
#             cy.get('p').eq(5).contains('e2e tests:')
#             cy.get('p').eq(5).contains('Cypress')
#             cy.get('p').eq(6).contains('api tests:')
#             cy.get('p').eq(6).contains('RSpec')      
#           })
#       cy.get('h3.tools')
#         .next('div.aligned-columns')
#           .within(() => {
#             cy.get('p').eq(0).contains('user avatars:')
#             cy.get('p').eq(0).contains('local active storage')
#             cy.get('p').eq(1).contains('backend auth:')
#             cy.get('p').eq(1).contains('bcrypt & jwt')
#             cy.get('p').eq(2).contains('frontend auth:')
#             cy.get('p').eq(2).contains('nuxt auth module')
#           }) 
#     })
#   })

#   describe('Log In Copy', () => {
#     it('should find page copy', () => {
#       cy.visit('http://localhost:3001/log-in')
#       cy.get('main.container')
#         .should('contain', 'Email')
#         .should('contain', 'Password')
#         .should('contain', 'Log In')
#         .should('contain', "Don't have an account")
#     })
#   })

#   describe('Sign Up Copy', () => {
#     it('should find page copy', () => {
#       cy.visit('http://localhost:3001/sign-up')
#       cy.get('main.container')
#         .should('contain', 'Name')
#         .should('contain', 'Email')
#         .should('contain', 'Avatar')
#         .should('contain', 'Password')
#         .should('contain', 'Create User')
#     })
#   })
# })
# ~
# EOF
# cat <<'EOF' | puravida cypress/e2e/sign-up-flow.cy.js ~
# /// <reference types="cypress" />

# // reset the db: db:drop db:create db:migrate db:seed RAILS_ENV=test
# // run dev server with test db: CYPRESS=1 bin/rails server -p 3000
# describe('Sign Up Flow', () => {
#   it('Should redirect to user show page', () => {
#     cy.visit('http://localhost:3001/sign-up')
#     cy.get('p').contains('Name').next('input').type('name')
#     cy.get('p').contains('Email').next('input').type('test' + Math.random().toString(36).substring(2, 15) + '@mail.com')
#     cy.get('p').contains('Email').next('input').type('test' + Math.random().toString(36).substring(2, 15) + '@mail.com')
#     cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/dwight-schrute.png')
#     cy.get('p').contains('Password').next('input').type('password')
#     cy.get('button').contains('Create User').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/\d+/)
#     cy.get('h2').should('contain', 'name')
#     // TODO: assert avatar presence
#     // cy.logout()
#   })
# })
# ~
# EOF
# cat <<'EOF' | puravida cypress/e2e/log-in-flow.cy.js ~
# /// <reference types="cypress" />

# // reset the db: db:drop db:create db:migrate db:seed RAILS_ENV=test
# // run dev server with test db: CYPRESS=1 bin/rails server -p 3000

# describe('Manual Login', () => {
#   it('Should log in user', () => {
#     cy.intercept('POST', '/login').as('login')
#     cy.loginAdmin()
#     cy.wait('@login').then(({response}) => {
#       expect(response.statusCode).to.eq(200)
#     })
#     cy.url().should('eq', 'http://localhost:3001/users/1')
#     cy.get('h2').should('contain', 'Michael Scott')
#     cy.logoutAdmin()
#   })
# })

# context('Mocked Request Login', () => {
#   describe('Login with real email', () => {
#     it('Should get 200 response', () => {
#       cy.visit('http://localhost:3001/log-in')
#       cy.request(
#         { url: 'http://localhost:3000/login', method: 'POST', body: { email: 'michaelscott@dundermifflin.com', 
#         password: 'password' }, failOnStatusCode: false })
#         .its('status').should('equal', 200)
#       cy.get('h2').should('contain', 'Log In')
#       cy.url().should('include', '/log-in')
#     })
#   })

#   describe('Login with fake email', () => {
#     it('Should get 401 response', () => {
#       cy.visit('http://localhost:3001/log-in')
#       cy.request(
#         { url: 'http://localhost:3000/login', method: 'POST', body: { email: 'xyz@dundermifflin.com', 
#         password: 'password' }, failOnStatusCode: false })
#         .its('status').should('equal', 401)
#       cy.get('h2').should('contain', 'Log In')
#       cy.url().should('include', '/log-in')
#     })
#   })
# })
# ~
# EOF
# cat <<'EOF' | puravida cypress/e2e/admin.cy.js ~
# /// <reference types="cypress" />

# // reset the db: rails db:drop db:create db:migrate db:seed RAILS_ENV=test
# // run dev server with test db: CYPRESS=1 bin/rails server -p 3000

# describe('Admin login', () => {
#   it('Should go to admin show page', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.get('h2').should('contain', 'Michael Scott')
#     cy.get('p').should('contain', 'id: 1')
#     cy.get('p').should('contain', 'avatar:')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*michael-scott.png/)
#     cy.get('p').should('contain', 'admin: true')
#     cy.logoutAdmin()
#   })
#   it('Should contain admin nav', () => {
#     cy.loginAdmin()
#     cy.get('nav ul.menu li a').should('contain', 'Admin')
#     cy.logoutAdmin()
#   })
# })

# describe('Admin nav', () => {
#   it('Should work', () => {
#     cy.loginAdmin()
#     cy.get('nav li a').contains('Admin').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/admin/)
#     cy.logoutAdmin()
#   })
# })

# describe('Admin page', () => {
#   it('Should have correct copy', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.visit('http://localhost:3001/admin')
#     cy.url().should('match', /http:\/\/localhost:3001\/admin/)
#     cy.get('p').eq(0).invoke('text').should('match', /Number of users: \d+/)
#     cy.get('p').eq(1).invoke('text').should('match', /Number of admins: \d+/)
#     cy.get('p').eq(2).contains('Users')
#     cy.get('p').eq(3).contains('Cars')
#     cy.logoutAdmin()
#   })
#   it('Should have correct links', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.visit('http://localhost:3001/admin')
#     cy.url().should('match', /http:\/\/localhost:3001\/admin/)
#     cy.get('p').contains('Users').should('have.attr', 'href', '/users')
#     cy.logoutAdmin()
#   })
#   it('Should have working links', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.visit('http://localhost:3001/admin')
#     cy.url().should('match', /http:\/\/localhost:3001\/admin/)
#     cy.get('p a').contains('Users').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users/)
#     cy.logoutAdmin()
#   })
# })

# describe('Edit user as admin', () => {
#   it('Should be successful', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.get('h2').children().eq(1).click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1\/edit/)
#     cy.get('p').contains('Name').next('input').clear()
#     cy.get('p').contains('Name').next('input').type('name')
#     cy.get('p').contains('Email').next('input').clear()
#     cy.get('p').contains('Email').next('input').type('name@mail.com')
#     cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/dwight-schrute.png')
#     cy.get('button').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.get('h2').should('contain', 'name')
#     cy.get('p').contains('email').should('contain', 'name@mail.com')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*dwight-schrute.png/)
#     cy.get('p').should('contain', 'admin: true')
#     cy.get('h2').children().eq(1).click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1\/edit/)
#     cy.get('p').contains('Name').next('input').clear()
#     cy.get('p').contains('Name').next('input').type('Michael Scott')
#     cy.get('p').contains('Email').next('input').clear()
#     cy.get('p').contains('Email').next('input').type('michaelscott@dundermifflin.com')
#     cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/michael-scott.png')
#     cy.get('button').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.get('h2').should('contain', 'Michael Scott')
#     cy.get('p').contains('email').should('contain', 'michaelscott@dundermifflin.com')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*michael-scott.png/)
#     cy.get('p').should('contain', 'admin: true')
#     cy.logoutAdmin()
#   })
# })

# describe('Admin /users page', () => {
#   it('Should show three users', () => {
#     cy.loginAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#     cy.visit('http://localhost:3001/users')
#     cy.url().should('match', /http:\/\/localhost:3001\/users/)
#     cy.get('section').children('div').should('have.length', 3)
#     cy.logoutAdmin()
#   })
# })

# describe('Admin visiting /cars', () => {

#   context('No query string', () => {
#     it("Should show admin's two cars", () => {
#       cy.loginAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#       cy.visit('http://localhost:3001/cars')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars/)
#       cy.get('section').children('div').should('have.length', 2)
#       cy.get('article').eq(0).find('h2').should('contain', 'Wrenches')
#       cy.get('article').eq(0).should('contain', "Michael's wrench")
#       cy.get('article').eq(1).find('h2').should('contain', 'Bolts')
#       cy.get('article').eq(1).should('contain', "Michael's bolt")
#       cy.logoutAdmin()
#     })
#   })


#   context('?admin=true query string', () => {
#     it("Should show all cars", () => {
#       cy.loginAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#       cy.visit('http://localhost:3001/cars?admin=true')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?admin=true/)
#       cy.get('section').children('div').should('have.length', 7)
#       cy.logoutAdmin()
#     })
#   })

#   context('user_id=1 query string', () => {
#     it("Should show user one's two cars", () => {
#       cy.loginAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#       cy.visit('http://localhost:3001/cars?user_id=1')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=1/)
#       cy.get('section').children('div').should('have.length', 2)
#       cy.get('article').eq(0).should('contain', "Michael's wrench")
#       cy.get('article').eq(1).should('contain', "Michael's bolt")
#       cy.logoutAdmin()
#     })
#   })

#   context('user_id=2 query string', () => {
#     it("Should show user two's three cars", () => {
#       cy.loginAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
#       cy.visit('http://localhost:3001/cars?user_id=2')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=2/)
#       cy.get('section').children('div').should('have.length', 3)
#       cy.get('article').eq(0).should('contain', "Jim's bracket")
#       cy.get('article').eq(1).should('contain', "Jim's nut")
#       cy.get('article').eq(2).should('contain', "Jim's pipe")
#       cy.logoutAdmin()
#     })
#   })
  
# })
# ~
# EOF
# cat <<'EOF' | puravida cypress/e2e/non-admin.cy.js ~
# /// <reference types="cypress" />

# // reset the db: rails db:drop db:create db:migrate db:seed RAILS_ENV=test
# // run dev server with test db: CYPRESS=1 bin/rails server -p 3000

# describe('Non-admin login', () => {
#   it('Should go to non-admin show page', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.get('h2').should('contain', 'Jim Halpert')
#     cy.get('p').should('contain', 'id: 2')
#     cy.get('p').should('contain', 'avatar:')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*jim-halpert.png/)
#     cy.get('p').contains('admin').should('not.exist')
#     cy.logoutNonAdmin()
#   })
#   it('Should not contain admin nav', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.get('nav ul.menu li a').contains('Admin').should('not.exist')
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users as non-admin', () => {
#   it('Should redirect to home', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users/1 as non-admin', () => {
#   it('Should go to non-admin show page', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users/1', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users/2 as non-admin user 2', () => {
#   it('Should go to user show page', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users/2', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/users\/2$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users/3 as non-admin user 2', () => {
#   it('Should go to home', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users/3', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users/1/edit as non-admin', () => {
#   it('Should go to non-admin show page', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users/1/edit', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Accessing /users/3/edit as non-admin', () => {
#   it('Should go to non-admin show page', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.visit('http://localhost:3001/users/3/edit', { failOnStatusCode: false } )
#     cy.url().should('match', /^http:\/\/localhost:3001\/$/)
#     cy.logoutNonAdmin()
#   })
# })

# describe('Edit self as non-admin', () => {
#   it('Edit should be successful', () => {
#     cy.loginNonAdmin()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.get('h2').contains('Jim Halpert').next('a').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2\/edit/)
#     cy.get('p').contains('Name').next('input').clear()
#     cy.get('p').contains('Name').next('input').type('name')
#     cy.get('p').contains('Email').next('input').clear()
#     cy.get('p').contains('Email').next('input').type('name@mail.com')
#     cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/dwight-schrute.png')
#     cy.get('button').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.get('h2').should('contain', 'name')
#     cy.get('p').contains('email').should('contain', 'name@mail.com')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*dwight-schrute.png/)
#     cy.get('p').contains('admin').should('not.exist')
#     cy.get('h2').children().eq(1).click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2\/edit/)
#     cy.get('p').contains('Name').next('input').clear()
#     cy.get('p').contains('Name').next('input').type('Jim Halpert')
#     cy.get('p').contains('Email').next('input').clear()
#     cy.get('p').contains('Email').next('input').type('jimhalpert@dundermifflin.com')
#     cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/jim-halpert.png')
#     cy.get('button').click()
#     cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#     cy.get('h2').should('contain', 'Jim Halpert')
#     cy.get('p').contains('email').should('contain', 'jimhalpert@dundermifflin.com')
#     cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*jim-halpert.png/)
#     cy.get('p').contains('admin').should('not.exist')
#     cy.logoutNonAdmin()
#   })
# })

# describe('Non-admin visiting /cars', () => {
#   context('No query string', () => {
#     it("Should redirect to home", () => {
#       cy.loginNonAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#       cy.visit('http://localhost:3001/cars')
#       cy.url().should('match', /http:\/\/localhost:3001\//)
#       cy.logoutNonAdmin()
#     })
#   })
#   context('?admin=true query string', () => {
#     it("Should redirect to home", () => {
#       cy.loginNonAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#       cy.visit('http://localhost:3001/cars?admin=true')
#       cy.url().should('match', /http:\/\/localhost:3001\//)
#       cy.logoutNonAdmin()
#     })
#   })
#   context('?user_id=1 query string', () => {
#     it("Should redirect to to ?user_id=2", () => {
#       cy.loginNonAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#       cy.visit('http://localhost:3001/cars?user_id=1')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=2/)
#       cy.get('article').should('have.length', 3)
#       cy.get('article').eq(0).should('contain', "Jim's bracket")
#       cy.get('article').eq(1).should('contain', "Jim's nut")
#       cy.get('article').eq(2).should('contain', "Jim's pipe")
#       cy.logoutNonAdmin()
#     })
#   })
#   context('?user_id=2 query string', () => {
#     it("Should show user's three cars", () => {
#       cy.loginNonAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#       cy.visit('http://localhost:3001/cars?user_id=2')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=2/)
#       cy.get('article').should('have.length', 3)
#       cy.get('article').eq(0).should('contain', "Jim's bracket")
#       cy.get('article').eq(1).should('contain', "Jim's nut")
#       cy.get('article').eq(2).should('contain', "Jim's pipe")
#       cy.logoutNonAdmin()
#     })
#   })
#   context('?user_id=3 query string', () => {
#     it("Should redirect to to ?user_id=2", () => {
#       cy.loginNonAdmin()
#       cy.url().should('match', /http:\/\/localhost:3001\/users\/2/)
#       cy.visit('http://localhost:3001/cars?user_id=3')
#       cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=2/)
#       cy.get('article').should('have.length', 3)
#       cy.get('article').eq(0).should('contain', "Jim's bracket")
#       cy.get('article').eq(1).should('contain', "Jim's nut")
#       cy.get('article').eq(2).should('contain', "Jim's pipe")
#       cy.logoutNonAdmin()
#     })
#   })
# })
# ~
# EOF


# echo -e "\n\n🦄 Deploy\n\n"

# cd ~/Desktop/back
# cat <<'EOF' | puravida fly.toml ~
# app = "ruxtmin-back"
# primary_region = "dfw"
# console_command = "/rails/bin/rails console"

# [build]

# [env]
#   RAILS_STORAGE = "/data"

# [[mounts]]
#   source = "ruxtmin_data"
#   destination = "/data"

# [http_service]
#   internal_port = 3000
#   force_https = true
#   auto_stop_machines = false
#   auto_start_machines = true
#   min_machines_running = 0
#   processes = ["app"]

# [[statics]]
#   guest_path = "/rails/public"
#   url_prefix = "/"
# ~
# puravida config/storage.yml ~
# test:
#   service: Disk
#   root: <%= Rails.root.join("tmp/storage") %>

# local:
#   service: Disk
#   root: <%= Rails.root.join("storage") %>

# production:
#   service: Disk
#   root: /data
# ~
# EOF
# cat <<'EOF' | puravida config/environmnets/production.rb ~
# require "active_support/core_ext/integer/time"
# Rails.application.configure do
#   config.cache_classes = true
#   config.eager_load = true
#   config.consider_all_requests_local       = false
#   config.public_file_server.enabled = ENV["RAILS_SERVE_STATIC_FILES"].present?
#   config.active_storage.service = :production
#   config.log_level = :info
#   config.log_tags = [ :request_id ]
#   config.action_mailer.perform_caching = false
#   config.i18n.fallbacks = true
#   config.active_support.report_deprecations = false
#   config.log_formatter = ::Logger::Formatter.new
#   if ENV["RAILS_LOG_TO_STDOUT"].present?
#     logger           = ActiveSupport::Logger.new(STDOUT)
#     logger.formatter = config.log_formatter
#     config.logger    = ActiveSupport::TaggedLogging.new(logger)
#   end
#   config.active_record.dump_schema_after_migration = false
# end
# ~
# EOF
# fly launch --copy-config --name ruxtmin-back --region dfw --yes
# fly deploy
# cd ~/Desktop/front
# npm run build
# fly launch --name ruxtmin-front --region dfw --yes
# fly deploy


# echo -e "\n\n🦄 DON'T FORGET TO SEED THE PROD USERS IN THE BACKEND!!!\n\n"

# echo -e "\n\n🦄 Have a nice day!\n\n"