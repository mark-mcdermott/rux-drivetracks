!/bin/bash
export PATH=/usr/local/bin:$PATH

echo -e "\n\n🦄 BACKEND\n\n"
cd ~/Desktop
rails new back --api --database=postgresql --skip-test-unit
cd back
rails db:drop db:create
bundle add rack-cors bcrypt jwt pry
bundle add rspec-rails --group "development, test"
bundle add database_cleaner-active_record --group "test"
bundle
rails active_storage:install
rails generate rspec:install
rails db:migrate
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets ~/Desktop/back/app/
puravida spec/fixtures/files
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/office-avatars/* ~/Desktop/back/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/cars/* ~/Desktop/back/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/maintenances/* ~/Desktop/back/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/documents/car-documents/contracts/* ~/Desktop/back/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/documents/car-documents/titles/* ~/Desktop/back/spec/fixtures/files/
cp -a ~/Desktop/fly-drivetracks-notes-and-assets/assets/images/documents/maintenance-documents/* ~/Desktop/back/spec/fixtures/files/
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
MIGRATION_FILE=$(find /Users/mmcdermott/Desktop/back/db/migrate -name "*_create_users.rb")
sed -i '' 3,10d $MIGRATION_FILE
awk 'NR==3 {print "\t\tcreate_table :users do |t|\n\t\t\tt.string :name, null: false\n\t\t\tt.string :email, null: false, index: { unique: true }\n\t\t\tt.boolean :admin, default: false\n\t\t\tt.string :password_digest\n\t\t\tt.timestamps\n\t\tend"} 1' $MIGRATION_FILE > temp.txt
mv temp.txt $MIGRATION_FILE
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
    # maintenances = Maintenance.where(car_id: cars).map { |maintenance| maintenance.id }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    # user['car_ids'] = cars
    # user['maintenance_ids'] = maintenances
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    # maintenances = Maintenance.where(car_id: car.id)
    # maintenances = maintenances.map { |maintenance| maintenance.slice(:id,:name,:description,:car_id) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:description)
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    # car['maintenances'] = maintenances
    car
  end

  def prep_raw_maintenance(maintenance)
    car_id = maintenance.car_id
    car = Car.find(car_id)
    user = User.find(car.user_id)
    image = maintenance.image.present? ? url_for(maintenance.image) : nil
    maintenance = maintenance.slice(:id,:name,:description)
    maintenance['carId'] = car_id
    maintenance['carName'] = car.name
    maintenance['carDescription'] = car.description
    maintenance['userId'] = user.id
    maintenance['userName'] = user.name
    maintenance['image'] = image
    maintenance
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
rails g scaffold Car name image:attachment year:integer make model trim body color plate vin cost:decimal initial_mileage:integer purchase_date:date purchase_vendor user:references
MIGRATION_FILE=$(find /Users/mmcdermott/Desktop/back/db/migrate -name "*_create_cars.rb")
sed -i '' 3,20d $MIGRATION_FILE
awk 'NR==3 {print "\t\tcreate_table :cars do |t|\n\t\t\tt.string :name, null: false\n\t\t\tt.integer :year\n\t\t\tt.string :make\n\t\t\tt.string :model\n\t\t\tt.string :trim\n\t\t\tt.string :body\n\t\t\tt.string :color\n\t\t\tt.string :plate\n\t\t\tt.string :vin\n\t\t\tt.decimal :cost, precision: 10, scale: 2\n\t\t\tt.integer :initial_mileage\n\t\t\tt.date :purchase_date\n\t\t\tt.string :purchase_vendor\n\t\t\tt.references :user, null: false, foreign_key: {on_delete: :cascade}\n\t\t\tt.timestamps\n\t\tend"} 1' $MIGRATION_FILE > temp.txt
mv temp.txt $MIGRATION_FILE
rails db:migrate
cat <<'EOF' | puravida app/models/car.rb ~
class Car < ApplicationRecord
  belongs_to :user
  has_one_attached :image
  validates :name, presence: true, allow_blank: false, length: { minimum: 4, maximum: 254 }
end
~
EOF
cat <<'EOF' | puravida app/models/user.rb ~
class User < ApplicationRecord
  has_many :cars, dependent: :destroy
  has_one_attached :avatar
  has_secure_password
  validates :email, format: { with: /\A(.+)@(.+)\z/, message: "Email invalid" }, uniqueness: { case_sensitive: false }, length: { minimum: 4, maximum: 254 }
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
    # maintenances = Maintenance.where(car_id: cars).map { |maintenance| maintenance.id }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    user['car_ids'] = car_ids
    user['cars'] = cars
    # user['maintenance_ids'] = maintenances
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    # maintenances = Maintenance.where(car_id: car.id)
    # maintenances = maintenances.map { |maintenance| maintenance.slice(:id,:name,:description,:car_id) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:year,:make,:model,:trim,:body,:color,:plate,:vin,:cost,:initial_mileage,:purchase_date,:purchase_vendor)
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    # car['maintenances'] = maintenances
    car
  end

  def prep_raw_maintenance(maintenance)
    car_id = maintenance.car_id
    car = Car.find(car_id)
    user = User.find(car.user_id)
    image = maintenance.image.present? ? url_for(maintenance.image) : nil
    maintenance = maintenance.slice(:id,:name,:description)
    maintenance['carId'] = car_id
    maintenance['carName'] = car.name
    maintenance['carDescription'] = car.description
    maintenance['userId'] = user.id
    maintenance['userName'] = user.name
    maintenance['image'] = image
    maintenance
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
      params.permit(:id, :name, :image, :year, :make, :model, :trim, :body, :color, :plate, :vin, :cost, :initial_mileage, :purchase_date, :purchase_vendor, :user_id)
    end
end
~
EOF
cat <<'EOF' | puravida spec/fixtures/cars.yml ~
fiat:
  name: Michael's Fiat 500
  make: Fiat
  model: 500
  trim: Sport
  color: Yellow
  body: Hatchback
  plate: 6XYK922
  vin: 3C3CFFBR0CT382584
  year: 2012, 
  cost: 10235.00
  purchase_vendor: Ted Fleid
  initial_mileage: 47361
  purchase_date: Date.parse(20180606)
  user: michael

civic:
  name: Michael's Honda Civic
  make: Honda
  model: Civic
  trim: Vp
  color: Blue
  body: Sedan
  plate: 4HGJ708
  vin: 2HGEJ6618XH589506
  year: 1999
  cost: 10352
  purchase_vendor: Howdy Honda
  initial_mileage: 78032
  purchase_date: Date.parse(20160713)
  user: michael

elantra:
  name: Jim's Hyundai Elantra
  make: Hyundai
  model: Elantra
  trim: GLS
  color: Black
  body: Sedan
  plate: 8CEU662
  vin: KMHDU46D17U090264
  year: 2007
  cost: 15000.00
  purchase_vendor: Feit Hyundai
  initial_mileage: 53032, 
  purchase_date: Date.parse(20200115)
  user: jim

leaf:
  name: Jim's Nissan Leaf
  make: Nissan
  model: Leaf
  trim: SV
  color: Silver
  body: Hatchback
  plate: ABC123
  vin: 1N4AZ1CP8LC310110
  year: 2020
  cost: 22590.00
  purchase_vendor: Carvana
  initial_mileage: 21440
  purchase_date: Date.parse(20230429)
  user: jim

scion:
  name: Pam's Scion Xb
  make: Scion
  model: Xb
  trim: Base / Parklan Edition
  color: Gray
  body: Wagon
  plate: 7MBE060
  vin: JTLZE4FE0FJ074884
  year: 2015
  cost: 25867.00
  purchase_vendor: Craigslist
  initial_mileage: 35631
  purchase_date: Date.parse(20201109)
  user: pam

camry:
  name: Pam's Toyota Camry
  make: Toyota
  model: Camry
  trim: LE
  color: Black
  body: Sedan
  plate: HDH1439
  vin: 4T1BE46K49U358097
  year: 2009
  cost: 7300
  purchase_vendor: Tanne Toyota
  initial_mileage: 134087
  purchase_date: Date.parse(20100513)
  user: pam
~
EOF
cat <<'EOF' | puravida spec/models/car_spec.rb ~
require 'rails_helper'

RSpec.describe "/cars", type: :request do
  fixtures :users, :cars
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:valid_attributes) {{ 
    name: "Jim's Fiat 500",
    make: "Fiat",
    model: "500",
    trim: "Sport",
    color: "Yellow",
    body: "Hatchback",
    plate: "6XYK922",
    vin: "3C3CFFBR0CT382584",
    year: 2012,
    cost: 10235.00,
    purchase_vendor: "Ted Fleid",
    initial_mileage: 47361,
    user_id: User.find_by(email: "michaelscott@dundermifflin.com").id
  }}
  let(:invalid_attributes) {{ 
    name: "",
    make: "Fiat",
    model: "500",
    trim: "Sport",
    color: "Yellow",
    body: "Hatchback",
    plate: "6XYK922",
    vin: "3C3CFFBR0CT382584",
    year: 2012,
    cost: 10235.00,
    purchase_vendor: "Ted Fleid",
    initial_mileage: 47361,
    user_id: User.find_by(email: "michaelscott@dundermifflin.com").id
  }}

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
  fixtures :users, :cars
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:valid_attributes) {{ 
    name: "Jim's Fiat 500",
    make: "Fiat",
    model: "500",
    trim: "Sport",
    color: "Yellow",
    body: "Hatchback",
    plate: "6XYK922",
    vin: "3C3CFFBR0CT382584",
    year: 2012,
    cost: 10235.00,
    purchase_vendor: "Ted Fleid",
    initial_mileage: 47361,
    user_id: User.find_by(email: "michaelscott@dundermifflin.com").id
  }}
  let(:invalid_attributes) {{ 
    name: "",
    make: "Fiat",
    model: "500",
    trim: "Sport",
    color: "Yellow",
    body: "Hatchback",
    plate: "6XYK922",
    vin: "3C3CFFBR0CT382584",
    year: 2012,
    cost: 10235.00,
    purchase_vendor: "Ted Fleid",
    initial_mileage: 47361,
    user_id: User.find_by(email: "michaelscott@dundermifflin.com").id
  }}

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
      expect(fiat['userName']).to eq "Michael Scott"
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
      expect(fiat['make']).to eq "Fiat"
      expect(fiat['model']).to eq "500"
      expect(fiat['trim']).to eq "Sport"
      expect(fiat['color']).to eq "Yellow"
      expect(fiat['body']).to eq "Hatchback"
      expect(fiat['plate']).to eq "6XYK922"
      expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
      expect(fiat['year']).to eq 2012
      expect(fiat['cost']).to eq "10235.0"
      expect(fiat['purchase_vendor']).to eq "Ted Fleid"
      expect(fiat['initial_mileage']).to eq 47361
      expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
    end
    it "second car has correct properties" do
      get cars_url, headers: valid_headers
      cars = JSON.parse(response.body)
      elantra = cars.find { |car| car['name'] == "Jim's Hyundai Elantra" }
      expect(elantra['name']).to eq "Jim's Hyundai Elantra"
      expect(elantra['userName']).to eq "Jim Halpert"
      expect(elantra['image']).to be_kind_of(String)
      expect(elantra['image']).to match(/http.*hyundai-elantra\.jpg/)
      expect(elantra['make']).to eq "Hyundai"
      expect(elantra['model']).to eq "Elantra"
      expect(elantra['trim']).to eq "GLS"
      expect(elantra['color']).to eq "Black"
      expect(elantra['body']).to eq "Sedan"
      expect(elantra['plate']).to eq "8CEU662"
      expect(elantra['vin']).to eq "KMHDU46D17U090264"
      expect(elantra['year']).to eq 2007
      expect(elantra['cost']).to eq "15000.0"
      expect(elantra['purchase_vendor']).to eq "Feit Hyundai"
      expect(elantra['initial_mileage']).to eq 53032
      expect(elantra['userId']).to eq User.find_by(email: "jimhalpert@dundermifflin.com").id
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
      expect(fiat['userName']).to eq "Michael Scott"
      expect(fiat['image']).to be_kind_of(String)
      expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
      expect(fiat['make']).to eq "Fiat"
      expect(fiat['model']).to eq "500"
      expect(fiat['trim']).to eq "Sport"
      expect(fiat['color']).to eq "Yellow"
      expect(fiat['body']).to eq "Hatchback"
      expect(fiat['plate']).to eq "6XYK922"
      expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
      expect(fiat['year']).to eq 2012
      expect(fiat['cost']).to eq "10235.0"
      expect(fiat['purchase_vendor']).to eq "Ted Fleid"
      expect(fiat['initial_mileage']).to eq 47361
      expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
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

      it "updates car's name" do
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
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['make']).to eq "Fiat"
        expect(fiat['model']).to eq "500"
        expect(fiat['trim']).to eq "Sport"
        expect(fiat['color']).to eq "Yellow"
        expect(fiat['body']).to eq "Hatchback"
        expect(fiat['plate']).to eq "6XYK922"
        expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
        expect(fiat['year']).to eq 2012
        expect(fiat['cost']).to eq "10235.0"
        expect(fiat['purchase_vendor']).to eq "Ted Fleid"
        expect(fiat['initial_mileage']).to eq 47361
        expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
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
  fixtures :users, :cars
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
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['make']).to eq "Fiat"
        expect(fiat['model']).to eq "500"
        expect(fiat['trim']).to eq "Sport"
        expect(fiat['color']).to eq "Yellow"
        expect(fiat['body']).to eq "Hatchback"
        expect(fiat['plate']).to eq "6XYK922"
        expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
        expect(fiat['year']).to eq 2012
        expect(fiat['cost']).to eq "10235.0"
        expect(fiat['purchase_vendor']).to eq "Ted Fleid"
        expect(fiat['initial_mileage']).to eq 47361
        expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['userName']).to eq "Michael Scott"
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq "Honda"
        expect(civic['model']).to eq "Civic"
        expect(civic['trim']).to eq "Vp"
        expect(civic['color']).to eq "Blue"
        expect(civic['body']).to eq "Sedan"
        expect(civic['plate']).to eq "4HGJ708"
        expect(civic['vin']).to eq "2HGEJ6618XH589506"
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq "10352.0"
        expect(civic['purchase_vendor']).to eq "Howdy Honda"
        expect(civic['initial_mileage']).to eq 78032
        expect(civic['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
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
        expect(elantra['userName']).to eq "Jim Halpert"
        expect(elantra['image']).to be_kind_of(String)
        expect(elantra['image']).to match(/http.*hyundai-elantra\.jpg/)
        expect(elantra['make']).to eq "Hyundai"
        expect(elantra['model']).to eq "Elantra"
        expect(elantra['trim']).to eq "GLS"
        expect(elantra['color']).to eq "Black"
        expect(elantra['body']).to eq "Sedan"
        expect(elantra['plate']).to eq "8CEU662"
        expect(elantra['vin']).to eq "KMHDU46D17U090264"
        expect(elantra['year']).to eq 2007
        expect(elantra['cost']).to eq "15000.0"
        expect(elantra['purchase_vendor']).to eq "Feit Hyundai"
        expect(elantra['initial_mileage']).to eq 53032
        expect(elantra['userId']).to eq User.find_by(email: "jimhalpert@dundermifflin.com").id
        expect(leaf['name']).to eq "Jim's Nissan Leaf"
        expect(leaf['userName']).to eq "Jim Halpert"
        expect(leaf['image']).to be_kind_of(String)
        expect(leaf['image']).to match(/http.*nissan-leaf\.jpg/)
        expect(leaf['make']).to eq "Nissan"
        expect(leaf['model']).to eq "Leaf"
        expect(leaf['trim']).to eq "SV"
        expect(leaf['color']).to eq "Silver"
        expect(leaf['body']).to eq "Hatchback"
        expect(leaf['plate']).to eq "ABC123"
        expect(leaf['vin']).to eq "1N4AZ1CP8LC310110"
        expect(leaf['year']).to eq 2020
        expect(leaf['cost']).to eq "22590.0"
        expect(leaf['purchase_vendor']).to eq "Carvana"
        expect(leaf['initial_mileage']).to eq 21440
        expect(leaf['userId']).to eq User.find_by(email: "jimhalpert@dundermifflin.com").id
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
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['userName']).to eq "Michael Scott"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['make']).to eq "Fiat"
        expect(fiat['model']).to eq "500"
        expect(fiat['trim']).to eq "Sport"
        expect(fiat['color']).to eq "Yellow"
        expect(fiat['body']).to eq "Hatchback"
        expect(fiat['plate']).to eq "6XYK922"
        expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
        expect(fiat['year']).to eq 2012
        expect(fiat['cost']).to eq "10235.0"
        expect(fiat['purchase_vendor']).to eq "Ted Fleid"
        expect(fiat['initial_mileage']).to eq 47361
        expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(civic['userName']).to eq "Michael Scott"
        expect(civic['image']).to be_kind_of(String)
        expect(civic['image']).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq "Honda"
        expect(civic['model']).to eq "Civic"
        expect(civic['trim']).to eq "Vp"
        expect(civic['color']).to eq "Blue"
        expect(civic['body']).to eq "Sedan"
        expect(civic['plate']).to eq "4HGJ708"
        expect(civic['vin']).to eq "2HGEJ6618XH589506"
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq "10352.0"
        expect(civic['purchase_vendor']).to eq "Howdy Honda"
        expect(civic['initial_mileage']).to eq 78032
        expect(civic['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
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
        expect(url_for(fiat['image'])).to be_kind_of(String)
        expect(url_for(fiat['image'])).to match(/http.*fiat-500\.jpg/)
        expect(fiat['name']).to eq "Michael's Fiat 500"
        expect(fiat['image']).to be_kind_of(String)
        expect(fiat['image']).to match(/http.*fiat-500\.jpg/)
        expect(fiat['make']).to eq "Fiat"
        expect(fiat['model']).to eq "500"
        expect(fiat['trim']).to eq "Sport"
        expect(fiat['color']).to eq "Yellow"
        expect(fiat['body']).to eq "Hatchback"
        expect(fiat['plate']).to eq "6XYK922"
        expect(fiat['vin']).to eq "3C3CFFBR0CT382584"
        expect(fiat['year']).to eq 2012
        expect(fiat['cost']).to eq "10235.0"
        expect(fiat['purchase_vendor']).to eq "Ted Fleid"
        expect(fiat['initial_mileage']).to eq 47361
        expect(fiat['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
        expect(civic['name']).to eq "Michael's Honda Civic"
        expect(url_for(civic['image'])).to be_kind_of(String)
        expect(url_for(civic['image'])).to match(/http.*honda-civic\.jpg/)
        expect(civic['make']).to eq "Honda"
        expect(civic['model']).to eq "Civic"
        expect(civic['trim']).to eq "Vp"
        expect(civic['color']).to eq "Blue"
        expect(civic['body']).to eq "Sedan"
        expect(civic['plate']).to eq "4HGJ708"
        expect(civic['vin']).to eq "2HGEJ6618XH589506"
        expect(civic['year']).to eq 1999
        expect(civic['cost']).to eq "10352.0"
        expect(civic['purchase_vendor']).to eq "Howdy Honda"
        expect(civic['initial_mileage']).to eq 78032
        expect(civic['userId']).to eq User.find_by(email: "michaelscott@dundermifflin.com").id
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


echo -e "\n\n🦄  Maintenances (Backend)\n\n"
rails g scaffold maintenance date:date description vendor cost:decimal images:attachments car:references
MIGRATION_FILE=$(find /Users/mmcdermott/Desktop/back/db/migrate -name "*_create_maintenances.rb")
sed -i '' 3,11d $MIGRATION_FILE
awk 'NR==3 {print "\t\tcreate_table :maintenances do |t|\n\t\t\tt.date :date\n\t\t\tt.string :description\n\t\t\tt.string :vendor\n\t\t\tt.decimal :cost, precision: 10, scale: 2\n\t\t\tt.references :car, null: false, foreign_key: {on_delete: :cascade}\n\t\t\tt.timestamps\n\t\tend"} 1' $MIGRATION_FILE > temp.txt
mv temp.txt $MIGRATION_FILE
rails db:migrate

cat <<'EOF' | puravida app/models/maintenance.rb ~
class Maintenance < ApplicationRecord
  belongs_to :car
  has_many_attached :images
  validates :date, presence: true
  validates :description, presence: true
end
~
EOF
cat <<'EOF' | puravida app/models/car.rb ~
class Car < ApplicationRecord
  belongs_to :user
  has_many :maintenances, dependent: :destroy
  has_one_attached :image
  validates :name, presence: true, allow_blank: false, length: { minimum: 4, maximum: 254 }
end
~
EOF
cat <<'EOF' | puravida spec/models/maintenance_spec.rb ~
require 'rails_helper'

RSpec.describe Maintenance, type: :model do
  fixtures :users, :cars, :maintenances
  let(:valid_attributes) {{ 
    date: Date.parse("20200713"),
    description: "Alignment",
    vendor: "Pep Boys",
    cost: 350.00,
    car_id: cars(:fiat).id
  }}
  let(:invalid_attributes) {{ 
    date: Date.parse("20200713"),
    description: nil,
    vendor: "Pep Boys",
    cost: 350.00,
    car_id: cars(:fiat).id
  }}

  it "is valid with valid attributes" do
    expect(Maintenance.new(valid_attributes)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(Maintenance.new(invalid_attributes)).to_not be_valid
  end

end
~
EOF
cat <<'EOF' | puravida app/controllers/maintenances_controller.rb ~
class MaintenancesController < ApplicationController
  before_action :set_maintenance, only: %i[ show update destroy ]

  # GET /maintenances
  def index
    if params['user_id'].present?
      @maintenances = Maintenance.joins(car: [:user]).where(users: {id: params['user_id']}).map { |maintenance| prep_raw_maintenance(maintenance) }
    else
      @maintenances = Maintenance.all.map { |maintenance| prep_raw_maintenance(maintenance) }
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
    create_params['images'] = params['images'].blank? ? nil : params['images'] # if no image is chosen on new maintenance page, params['image'] comes in as a blank string, which throws a 500 error at Maintenance.new(create_params). This changes any params['image'] blank string to nil, which is fine in Maintenance.new(create_params).
    create_params['car_id'] = create_params['car_id'].to_i
    @maintenance = Maintenance.new(create_params)
    if @maintenance.save
      render json: prep_raw_maintenance(@maintenance), status: :created, location: @maintenance
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
      params.permit(:id, :date, :description, :vendor, :cost, :images, :car_id)
    end
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
    maintenances_ids = Maintenance.where(car_id: car_ids).map { |maintenance| maintenance.id }
    maintenances = Maintenance.where(car_id: car_ids).map { |maintenance| prep_raw_maintenance(maintenance) }
    # documents = Document.where(car_id: cars).map { |document| document.id }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
    user['avatar'] = avatar
    user['car_ids'] = car_ids
    user['cars'] = cars
    user['maintenances_ids'] = maintenances_ids
    user['maintenances'] = maintenances
    # user['document_ids'] = documents
    user
  end

  def prep_raw_car(car)
    user_id = car.user_id
    user_name = User.find(car.user_id).name
    maintenances = Maintenance.where(car_id: car.id).map { |maintenance| prep_raw_maintenance(maintenance) }
    # documents = Document.where(car_id: car.id)
    # documents = documents.map { |document| document.slice(:id,:name,:description,:car_id) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:year,:make,:model,:trim,:body,:color,:plate,:vin,:cost,:initial_mileage,:purchase_date,:purchase_vendor)
    car['userId'] = user_id
    car['userName'] = user_name
    car['image'] = image
    car['maintenances'] = maintenances
    # car['documents'] = documents
    car
  end

  def prep_raw_maintenance(maintenance)
    car = Car.find(maintenance.car_id)
    user = User.find(car.user_id)
    images = maintenance.images.map { |image| url_for(image) }
    maintenance = maintenance.slice(:id,:date,:description,:vendor,:cost,:car_id)
    maintenance['carId'] = car.id
    maintenance['carName'] = car.name
    maintenance['userId'] = user.id
    maintenance['userName'] = user.name
    maintenance['images'] = images
    maintenance
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

cat <<'EOF' | puravida spec/fixtures/maintenances.yml ~
fiat_alignment:
  date: Date.parse("20200713")
  description: "Alignment"
  vendor: "Pep Boys"
  cost: 350.00
  car: fiat

fiat_oil_change:
  date: Date.parse("20210812")
  description: "Oil Change"
  vendor: "Jiffy Lube"
  cost: 78.00
  car: fiat

civic_brake_repair:
  date: Date.parse("20170123")
  description: "Brake Repair"
  vendor: "WalMart"
  cost: 400.00
  car: civic

civic_tire_rotation:
  date: Date.parse("20200311")
  description: "Tire Rotation"
  vendor: "Goodyear"
  cost: 105.00
  car: civic

elantra_new_tires:
  date: Date.parse("20200111")
  description: "New Tires"
  vendor: "Scott's"
  cost: 812.00
  car: elantra

elantra_repaired_body:
  date: Date.parse("20230627")
  description: "Repaired Body Dents"
  vendor: "Tenede Auto"
  cost: 1343.00
  car: elantra

leaf_windshield_replacement:
  date: Date.parse("20150614")
  description: "Windshield Replacement"
  vendor: "45th St. Car Repair"
  cost: 800.00
  car: leaf

leaf_new_spark_plugs:
  date: Date.parse("20170811")
  description: "New Spark Plugs"
  vendor: "Jim & Tony's Automotive Service"
  cost: 5.00
  car: leaf

scion_engine_overhaul:
  date: Date.parse("20200909")
  description: "Engine Overhaul"
  vendor: "Auto Stoppe"
  cost: 5932.00
  car: scion

scion_5k_mile_maintenance:
  date: Date.parse("20201030")
  description: "50,000 Mile Maintenance"
  vendor: "Dealership"
  cost: 0
  car: scion

camry_fuel_line:
  date: Date.parse("20220903")
  description: "Fuel Line Replacement"
  vendor: "Foreign Auto Austin"
  cost: 37.00
  car: camry

camry_replaced_radiator:
  date: Date.parse("20230601")
  description: "Replaced Radiator"
  vendor: "Blan's Auto Repair"
  cost: 400.00
  car: camry
~
EOF
cat <<'EOF' | puravida spec/requests/maintenances_spec.rb ~
# frozen_string_literal: true

require 'rails_helper'
RSpec.describe "/maintenances", type: :request do
  fixtures :users
  fixtures :cars
  fixtures :maintenances
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:valid_attributes) {{ 
    date: Date.parse("20200713"),
    description: "Alignment",
    vendor: "Pep Boys",
    cost: 350.00,
    car_id: cars(:fiat).id
  }}
  let(:invalid_attributes) {{ 
    date: Date.parse("20200713"),
    description: nil,
    vendor: "Pep Boys",
    cost: 350.00,
    car_id: cars(:fiat).id
  }}

  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
    @ryan_token = token_from_email_password("ryanhoward@dundermifflin.com", "password")
  end

  before :each do
    @fiat_alignment = maintenances(:fiat_alignment)
    @fiat_alignment.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-2.jpg'),'image/jpeg')])
    @fiat_oil_change = maintenances(:fiat_oil_change)
    @fiat_oil_change.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-2.jpg'),'image/jpeg')])
    @civic_brake_repair = maintenances(:civic_brake_repair)
    @civic_brake_repair.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-2.jpg'),'image/jpeg')])
    @civic_tire_rotation = maintenances(:civic_tire_rotation)
    @civic_tire_rotation.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-2.jpg'),'image/jpeg')])
    @elantra_new_tires = maintenances(:elantra_new_tires)
    @elantra_new_tires.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-2.jpg'),'image/jpeg')])
    @elantra_repaired_body = maintenances(:elantra_repaired_body)
    @elantra_repaired_body.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-2.jpg'),'image/jpeg')])
    @leaf_windshield_replacement = maintenances(:leaf_windshield_replacement)
    @leaf_windshield_replacement.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-2.jpg'),'image/jpeg')])
    @leaf_new_spark_plugs = maintenances(:leaf_new_spark_plugs)
    @leaf_new_spark_plugs.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-2.jpg'),'image/jpeg')])
    @scion_engine_overhaul = maintenances(:scion_engine_overhaul)
    @scion_engine_overhaul.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-2.jpg'),'image/jpeg')])
    @scion_5k_mile_maintenance = maintenances(:scion_5k_mile_maintenance)
    @scion_5k_mile_maintenance.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-2.jpg'),'image/jpeg')])
    @camry_fuel_line = maintenances(:camry_fuel_line)
    @camry_fuel_line.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-2.jpg'),'image/jpeg')])
    @camry_replaced_radiator = maintenances(:camry_replaced_radiator)
    @camry_replaced_radiator.images.attach([fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-1.jpg'),'image/jpeg'), fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-2.jpg'),'image/jpeg')])
  end

  describe "GET /index" do
    it "renders a successful response" do
      get maintenances_url, headers: valid_headers
      expect(response).to be_successful
    end
    it "gets twenty maintenances" do
      get maintenances_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 12
    end
    it "first maintenance has correct properties" do
      get maintenances_url, headers: valid_headers
      maintenances = JSON.parse(response.body)
      fiat = Car.find_by(name: "Michael's Fiat 500")
      michael = User.find_by(name: "Michael Scott")
      alignment = maintenances.find { |maintenance| maintenance['car_id'] == fiat.id and maintenance['cost'] == "350.0"}
      expect(alignment['date']).to eq "2020-07-13"
      expect(alignment['description']).to eq "Alignment"
      expect(alignment['vendor']).to eq "Pep Boys"
      expect(alignment['cost']).to eq "350.0"
      expect(alignment['carId']).to eq fiat.id
      expect(alignment['carName']).to eq fiat.name
      expect(alignment['userId']).to eq michael.id
      expect(alignment['userName']).to eq michael.name
    end
    it "second maintenance has correct properties" do
      get maintenances_url, headers: valid_headers
      maintenances = JSON.parse(response.body)
      elantra = Car.find_by(name: "Jim's Hyundai Elantra")
      jim = User.find_by(name: "Jim Halpert")
      tires = maintenances.find { |maintenance| maintenance['car_id'] == elantra.id and maintenance['cost'] == "812.0"}
      expect(tires['date']).to eq "2020-01-11"
      expect(tires['description']).to eq "New Tires"
      expect(tires['vendor']).to eq "Scott's"
      expect(tires['cost']).to eq "812.0"
      expect(tires['carId']).to eq elantra.id
      expect(tires['carName']).to eq elantra.name
      expect(tires['userId']).to eq jim.id
      expect(tires['userName']).to eq jim.name
    end
  end

  describe "GET /show" do
    it "renders a successful response" do
      maintenance = maintenances(:fiat_alignment)
      get maintenance_url(maintenance), headers: valid_headers
      expect(response).to be_successful
    end
    it "gets correct maintenance properties" do
      maintenance = maintenances(:fiat_alignment)
      fiat = cars(:fiat)
      michael = users(:michael)
      get maintenance_url(maintenance.id), headers: valid_headers
      fiat_alignment = JSON.parse(response.body)
      expect(fiat_alignment['date']).to eq "2020-07-13"
      expect(fiat_alignment['description']).to eq "Alignment"
      expect(fiat_alignment['vendor']).to eq "Pep Boys"
      expect(fiat_alignment['cost']).to eq "350.0"
      expect(fiat_alignment['carId']).to eq fiat.id
      expect(fiat_alignment['carName']).to eq "Michael's Fiat 500"
      expect(fiat_alignment['userId']).to eq michael.id
      expect(fiat_alignment['userName']).to eq michael.name
    end
  end

  describe "POST /create" do
    context "with valid parameters" do
      it "creates a new maintenance" do
        expect { post maintenances_url, params: valid_attributes, headers: valid_headers, as: :json
        }.to change(Maintenance, :count).by(1)
      end
      it "renders a JSON response with the new maintenance" do
        post maintenances_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end

    context "with invalid parameters" do
      it "does not create new maintenance" do
        expect {
          post maintenances_url, params: invalid_attributes, headers: valid_headers, as: :json
        }.to change(Maintenance, :count).by(0)
      end
      it "renders a JSON response with errors for the new car" do
        post maintenances_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end
  end

  describe "PATCH /update" do
    context "with valid parameters" do
      let(:new_attributes) {{ description: "UpdatedDescription"}}

      it "updates maintenance's description" do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        maintenance.reload
        expect(maintenance.description).to eq("UpdatedDescription")
      end

      it "renders a JSON response with the maintenance" do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including("application/json"))
      end

      it "maintenance's other properties are still correct" do
        fiat = cars(:fiat)
        michael = users(:michael)
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: new_attributes, headers: valid_headers, as: :json
        fiat_alignment = JSON.parse(response.body)
        expect(fiat_alignment['date']).to eq "2020-07-13"
        expect(fiat_alignment['vendor']).to eq "Pep Boys"
        expect(fiat_alignment['cost']).to eq "350.0"
        expect(fiat_alignment['carId']).to eq fiat.id
        expect(fiat_alignment['carName']).to eq "Michael's Fiat 500"
        expect(fiat_alignment['userId']).to eq michael.id
        expect(fiat_alignment['userName']).to eq michael.name
      end

    end

    context "with invalid parameters" do
      it "renders a JSON response with errors for the maintenance" do
        maintenance = maintenances(:fiat_alignment)
        patch maintenance_url(maintenance), params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end
  end

  describe "DELETE /destroy" do
    it "destroys the requested maintenance" do
      maintenance = Maintenance.create! valid_attributes
      expect { delete maintenance_url(maintenance), headers: valid_headers, as: :json
      }.to change(Maintenance, :count).by(-1)
    end
  end

end
~
EOF
echo -e "\n\n🦄  Routes\n\n"
cat <<'EOF' | puravida config/routes.rb ~
Rails.application.routes.draw do
  resources :users
  resources :cars
  resources :maintenances
  get "health", to: "health#index"
  post "login", to: "authentications#create"
  get "me", to: "application#user_from_token"
end
~
EOF
rspec

echo -e "\n\n🦄 Documents (Backend)\n\n"
rails g scaffold document date:date name notes:text attachment:attachment documentable:references{polymorphic}
rails db:migrate

cat <<'EOF' | puravida app/models/document.rb ~
class Document < ApplicationRecord
  belongs_to :documentable, polymorphic: true
  has_one_attached :attachment
end
~
EOF

cat <<'EOF' | puravida spec/fixtures/documents.yml ~
fiat_title:
  name: Fiat title
  documentable_type: Car
  documentable: fiat

fiat_contract:
  name: Fiat contract
  documentable_type: Car
  documentable: fiat

civic_title:
  name: civic title
  documentable_type: Car
  documentable: civic

civic_contract:
  name: civic contract
  documentable_type: Car
  documentable: civic

elantra_title:
  name: elantra title
  documentable_type: Car
  documentable: elantra

elantra_contract:
  name: elantra contract
  documentable_type: Car
  documentable: elantra

leaf_title:
  name: leaf title
  documentable_type: Car
  documentable: leaf

leaf_contract:
  name: leaf contract
  documentable_type: Car
  documentable: leaf

scion_title:
  name: scion title
  documentable_type: Car
  documentable: scion

scion_contract:
  name: scion contract
  documentable_type: Car
  documentable: scion

camry_title:
  name: camry title
  documentable_type: Car
  documentable: camry

camry_contract:
  name: camry contract
  documentable_type: Car
  documentable: camry

fiat_alignment_document_1:
  name: fiat_alignment_document_1
  documentable_type: Maintenance
  documentable: fiat_alignment

fiat_alignment_document_2:
  name: fiat_alignment_document_2
  documentable_type: Maintenance
  documentable: fiat_alignment

fiat_oil_change_document_1:
  name: fiat_oil_change_document_1
  documentable_type: Maintenance
  documentable: fiat_oil_change

fiat_oil_change_document_2:
  name: fiat_oil_change_document_2
  documentable_type: Maintenance
  documentable: fiat_oil_change

civic_brake_repair_document_1:
  name: civic_brake_repair_document_1
  documentable_type: Maintenance
  documentable: civic_brake_repair

civic_brake_repair_document_2:
  name: civic_brake_repair_document_2
  documentable_type: Maintenance
  documentable: civic_brake_repair

civic_tire_rotation_document_1:
  name: civic_tire_rotation_document_1
  documentable_type: Maintenance
  documentable: civic_tire_rotation

civic_tire_rotation_document_2:
  name: civic_tire_rotation_document_2
  documentable_type: Maintenance
  documentable: civic_tire_rotation

elantra_new_tires_document_1:
  name: elantra_new_tires_document_1
  documentable_type: Maintenance
  documentable: elantra_new_tires

elantra_new_tires_document_2:
  name: elantra_new_tires_document_2
  documentable_type: Maintenance
  documentable: elantra_new_tires

elantra_repaired_body_document_1:
  name: elantra_repaired_body_document_1
  documentable_type: Maintenance
  documentable: elantra_repaired_body

elantra_repaired_body_document_2:
  name: elantra_repaired_body_document_2
  documentable_type: Maintenance
  documentable: elantra_repaired_body

leaf_windshield_replacement_document_1:
  name: leaf_windshield_replacement_document_1
  documentable_type: Maintenance
  documentable: leaf_windshield_replacement

leaf_windshield_replacement_document_2:
  name: leaf_windshield_replacement_document_2
  documentable_type: Maintenance
  documentable: leaf_windshield_replacement

leaf_new_spark_plugs_document_1:
  name: leaf_new_spark_plugs_document_1
  documentable_type: Maintenance
  documentable: leaf_new_spark_plugs

leaf_new_spark_plugs_document_2:
  name: leaf_new_spark_plugs_document_2
  documentable_type: Maintenance
  documentable: leaf_new_spark_plugs

scion_engine_overhaul_document_1:
  name: scion_engine_overhaul_document_1
  documentable_type: Maintenance
  documentable: scion_engine_overhaul

scion_engine_overhaul_document_2:
  name: scion_engine_overhaul_document_2
  documentable_type: Maintenance
  documentable: scion_engine_overhaul

scion_5k_mile_maintenance_document_1:
  name: scion_5k_mile_maintenance_document_1
  documentable_type: Maintenance
  documentable: scion_5k_mile_maintenance

scion_5k_mile_maintenance_document_2:
  name: scion_5k_mile_maintenance_document_2
  documentable_type: Maintenance
  documentable: scion_5k_mile_maintenance

camry_fuel_line_document_1:
  name: camry_fuel_line_document_1
  documentable_type: Maintenance
  documentable: camry_fuel_line

camry_fuel_line_document_2:
  name: camry_fuel_line_document_2
  documentable_type: Maintenance
  documentable: camry_fuel_line

camry_replaced_radiator_document_1:
  name: camry_replaced_radiator_document_1
  documentable_type: Maintenance
  documentable: camry_replaced_radiator

camry_replaced_radiator_document_2:
  name: camry_replaced_radiator_document_2
  documentable_type: Maintenance
  documentable: camry_replaced_radiator
~
EOF

cat <<'EOF' | puravida app/models/car.rb ~
class Car < ApplicationRecord
  belongs_to :user
  has_many :maintenances, dependent: :destroy
  has_many :documents, :as => :documentable
  has_one_attached :image
  validates :name, presence: true, allow_blank: false, length: { minimum: 4, maximum: 254 }
end
~
EOF

cat <<'EOF' | puravida app/models/maintenance.rb ~
class Maintenance < ApplicationRecord
  belongs_to :car
  has_many_attached :images
  has_many :documents, :as => :documentable
  validates :date, presence: true
  validates :description, presence: true
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
    maintenances_ids = Maintenance.where(car_id: car_ids).map { |maintenance| maintenance.id }
    maintenances = Maintenance.where(car_id: car_ids).map { |maintenance| prep_raw_maintenance(maintenance) }
    documents_ids = Document.where(documentable_id: car_ids, documentable_type: "Car").map { |document| document.id }
    documents = Document.where(documentable_id: car_ids, documentable_type: "Car").map { |document| prep_raw_document(document) }
    user = user.admin ? user.slice(:id,:email,:name,:admin) : user.slice(:id,:email,:name)
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
    documents = Document.where(documentable_id: car.id, documentable_type: "Car").map { |document| prep_raw_document(document) }
    image = car.image.present? ? url_for(car.image) : nil
    car = car.slice(:id,:name,:year,:make,:model,:trim,:body,:color,:plate,:vin,:cost,:initial_mileage,:purchase_date,:purchase_vendor)
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
    images = maintenance.images.present? ? maintenance.images.map { |image| url_for(image) } : nil
    maintenance = maintenance.slice(:id,:date,:description,:vendor,:cost,:car_id)
    maintenance['carId'] = car.id
    maintenance['carName'] = car.name
    maintenance['userId'] = user.id
    maintenance['userName'] = user.name
    maintenance['images'] = images
    maintenance
  end

  def prep_raw_document(document)
    attachment_path = document.attachment.present? ? url_for(document.attachment) : nil
    attachment_file = attachment_path.present? ? File.basename(attachment_path) : nil
    documentable_type = document.documentable_type
    documentable_id = document.documentable_id
    document = document.slice(:id,:date,:name,:notes)
    document['attachment'] = attachment_path
    document['attachmentFile'] = attachment_file
    car_id = nil
    if documentable_type == "Car"
      car_id = documentable_id
    elsif documentable_type == "Maintenance"
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
  
  private 
  
    def auth_header
      request.headers['Authorization']
    end

end
~
EOF

cat <<'EOF' | puravida app/controllers/documents_controller.rb ~
class DocumentsController < ApplicationController
  before_action :set_document, only: %i[ show update destroy ]

  # GET /documents
  def index
    if params['user_id'].present?
      car_ids = Car.where(user_id: params['user_id']).map { |car| car.id }
      maintenance_ids = Maintenance.where(car_id: car_ids).map { |maintenance| maintenance.id }
      car_documents = Document.where(documentable_type: "Car", documentable_id: car_ids)
      maintenance_documents = Document.where(documentable_type: "Maintenance", documentable_id: maintenance_ids)
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
    create_params['attachment'] = params['attachment'].blank? ? nil : params['attachment'] # if no image is chosen on new maintenance page, params['image'] comes in as a blank string, which throws a 500 error at Maintenance.new(create_params). This changes any params['image'] blank string to nil, which is fine in Maintenance.new(create_params).
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
~
EOF


cat <<'EOF' | puravida spec/requests/documents_spec.rb ~
require 'rails_helper'

RSpec.describe "/documents", type: :request do
  fixtures :users, :cars, :maintenances, :documents
  let(:valid_headers) {{ Authorization: "Bearer " + @michael_token }}
  let(:valid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: maintenances(:fiat_alignment).id
  }}
  let(:invalid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: -1
  }}

  before :all do
    @michael_token = token_from_email_password("michaelscott@dundermifflin.com", "password")
  end

  before :each do
    @fiat_title = documents(:fiat_title)
    @fiat_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-fiat-500.gif'),'image/gif'))
    @fiat_contract = documents(:fiat_contract)
    @fiat_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-fiat-500.webp'),'image/webp'))
    @civic_title = documents(:civic_title)
    @civic_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-honda-civic.png'),'image/png'))
    @civic_contract = documents(:civic_contract)
    @civic_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-honda-civic.png'),'image/png'))
    @elantra_title = documents(:elantra_title)
    @elantra_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-hyundai-elantra.pdf'),'application/pdf'))
    @elantra_contract = documents(:elantra_contract)
    @elantra_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-hyundai-elantra.jpg'),'image/jpeg'))
    @leaf_title = documents(:leaf_title)
    @leaf_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-nissan-leaf.png'),'image/png'))
    @leaf_contract = documents(:leaf_contract)
    @leaf_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-nissan-leaf.png'),'image/png'))
    @scion_title = documents(:scion_title)
    @scion_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-scion.jpg'),'image/jpeg'))
    @scion_contract = documents(:scion_contract)
    @scion_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-scion.pdf'),'application/pdf'))
    @camry_title = documents(:camry_title)
    @camry_title.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'title-toyota-camry.jpg'),'image/jpeg'))
    @camry_contract = documents(:camry_contract)
    @camry_contract.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'contract-toyota-camry.jpg'),'image/jpeg'))
    @fiat_alignment_document_1 = documents(:fiat_alignment_document_1)
    @fiat_alignment_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-1.png'),'image/png'))
    @fiat_alignment_document_2 = documents(:fiat_alignment_document_2)
    @fiat_alignment_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-alignment-2.txt'),'text/plain'))
    @fiat_oil_change_document_1 = documents(:fiat_oil_change_document_1)
    @fiat_oil_change_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-1.txt'),'text/plain'))
    @fiat_oil_change_document_2 = documents(:fiat_oil_change_document_2)
    @fiat_oil_change_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'fiat-oil-change-2.txt'),'text/plain'))
    @civic_brake_repair_document_1 = documents(:civic_brake_repair_document_1)
    @civic_brake_repair_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-1.jpg'),'image/jpeg'))
    @civic_brake_repair_document_2 = documents(:civic_brake_repair_document_2)
    @civic_brake_repair_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-brake-repair-2.pdf'),'application/pdf'))
    @civic_tire_rotation_document_1 = documents(:civic_tire_rotation_document_1)
    @civic_tire_rotation_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-1.pdf'),'application/pdf'))
    @civic_tire_rotation_document_2 = documents(:civic_tire_rotation_document_2)
    @civic_tire_rotation_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'civic-tire-rotation-2.png'),'image/png'))
    @elantra_new_tires_document_1 = documents(:elantra_new_tires_document_1)
    @elantra_new_tires_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-1.pdf'),'application/pdf'))
    @elantra_new_tires_document_2 = documents(:elantra_new_tires_document_2)
    @elantra_new_tires_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-new-tires-2.pdf'),'application/pdf'))
    @elantra_repaired_body_document_1 = documents(:elantra_repaired_body_document_1)
    @elantra_repaired_body_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-1.png'),'image/png'))
    @elantra_repaired_body_document_2 = documents(:elantra_repaired_body_document_2)
    @elantra_repaired_body_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'elantra-repaired-body-2.pdf'),'application/pdf'))
    @leaf_windshield_replacement_document_1 = documents(:leaf_windshield_replacement_document_1)
    @leaf_windshield_replacement_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-1.webp'),'image/webp'))
    @leaf_windshield_replacement_document_2 = documents(:leaf_windshield_replacement_document_2)
    @leaf_windshield_replacement_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-windshield-replacement-2.webp'),'image/webp'))
    @leaf_new_spark_plugs_document_1 = documents(:leaf_new_spark_plugs_document_1)
    @leaf_new_spark_plugs_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-1.txt'),'text/plain'))
    @leaf_new_spark_plugs_document_2 = documents(:leaf_new_spark_plugs_document_2)
    @leaf_new_spark_plugs_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'leaf-new-spark-plugs-2.png'),'image/png'))
    @scion_engine_overhaul_document_1 = documents(:scion_engine_overhaul_document_1)
    @scion_engine_overhaul_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-1.png'),'image/png'))
    @scion_engine_overhaul_document_2 = documents(:scion_engine_overhaul_document_2)
    @scion_engine_overhaul_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-engine-overhaul-2.jpg'),'image/jpeg'))
    @scion_5k_mile_maintenance_document_1 = documents(:scion_5k_mile_maintenance_document_1)
    @scion_5k_mile_maintenance_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-1.jpg'),'image/jpeg'))
    @scion_5k_mile_maintenance_document_2 = documents(:scion_5k_mile_maintenance_document_2)
    @scion_5k_mile_maintenance_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'scion-5k-mile-maintenance-2.png'),'image/png'))
    @camry_fuel_line_document_1 = documents(:camry_fuel_line_document_1)
    @camry_fuel_line_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-1.txt'),'text/plain'))
    @camry_fuel_line_document_2 = documents(:camry_fuel_line_document_2)
    @camry_fuel_line_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-fuel-line-2.webp'),'image/webp'))
    @camry_replaced_radiator_document_1 = documents(:camry_replaced_radiator_document_1)
    @camry_replaced_radiator_document_1.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-1.png'),'image/png'))
    @camry_replaced_radiator_document_2 = documents(:camry_replaced_radiator_document_2)
    @camry_replaced_radiator_document_2.attachment.attach(fixture_file_upload(Rails.root.join('spec', 'fixtures', 'files', 'camry-replaced-radiator-2.webp'),'image/webp'))
  end

  describe "GET /index" do
    it "renders a successful response" do
      get documents_url, headers: valid_headers
      expect(response).to be_successful
    end
    it "gets 36 documents" do
      get documents_url, headers: valid_headers
      expect(JSON.parse(response.body).length).to eq 36
    end
    it "first document has correct properties" do
      get documents_url, headers: valid_headers
      documents = JSON.parse(response.body)
      fiat_title = documents.select{|document| document['name'] == "Fiat title"}[0]
      michael = User.find_by(name: "Michael Scott")
      fiat = Car.find_by(name: "Michael's Fiat 500")
      expect(fiat_title['date']).to be_nil
      expect(fiat_title['name']).to eq "Fiat title"
      expect(fiat_title['notes']).to be_nil
      expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
      expect(fiat_title['carId']).to eq fiat.id
      expect(fiat_title['carName']).to eq fiat.name
      expect(fiat_title['userId']).to eq michael.id
      expect(fiat_title['userName']).to eq michael.name
    end
    it "second document has correct properties" do
      get documents_url, headers: valid_headers
      documents = JSON.parse(response.body)
      elantra_tires = documents.select{|document| document['name'] == "elantra_new_tires_document_1"}[0]
      jim = User.find_by(name: "Jim Halpert")
      elantra = Car.find_by(name: "Jim's Hyundai Elantra")
      expect(elantra_tires['date']).to be_nil
      expect(elantra_tires['name']).to eq "elantra_new_tires_document_1"
      expect(elantra_tires['notes']).to be_nil
      expect(elantra_tires['attachment']).to match(/http.*elantra-new-tires-1\.pdf/)
      expect(elantra_tires['carId']).to eq elantra.id
      expect(elantra_tires['carName']).to eq elantra.name
      expect(elantra_tires['userId']).to eq jim.id
      expect(elantra_tires['userName']).to eq jim.name
    end
  end

  describe "GET /show" do
    it "renders a successful response" do
      document = documents(:fiat_title)
      get document_url(document), headers: valid_headers
      expect(response).to be_successful
    end
    it "document has correct properties" do
      document = documents(:fiat_title)
      fiat = cars(:fiat)
      michael = users(:michael)
      get document_url(document), headers: valid_headers
      fiat_title = JSON.parse(response.body)
      expect(fiat_title['date']).to be_nil
      expect(fiat_title['name']).to eq "Fiat title"
      expect(fiat_title['notes']).to be_nil
      expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
      expect(fiat_title['carId']).to eq fiat.id
      expect(fiat_title['carName']).to eq fiat.name
      expect(fiat_title['userId']).to eq michael.id
      expect(fiat_title['userName']).to eq michael.name
    end
  end

  describe "POST /create" do
    context "with valid parameters" do
      it "creates a new document" do
        expect { post documents_url, params: valid_attributes, headers: valid_headers, as: :json
        }.to change(Document, :count).by(1)
      end
      it "renders a JSON response with the new document" do
        post documents_url, params: valid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:created)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end

    context "with invalid parameters" do
      it "does not create new document" do
        expect {
          post documents_url, params: invalid_attributes, headers: valid_headers, as: :json
        }.to change(Document, :count).by(0)
      end
      it "renders a JSON response with errors for the new document" do
        post documents_url, params: invalid_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:unprocessable_entity)
        expect(response.content_type).to match(a_string_including("application/json"))
      end
    end
  end

  describe "PATCH /update" do
    context "with valid parameters" do
      let(:new_attributes) {{ name: "UpdatedName"}}

      it "updates document's description" do
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        document.reload
        expect(document.name).to eq("UpdatedName")
      end

      it "renders a JSON response with the document" do
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        expect(response).to have_http_status(:ok)
        expect(response.content_type).to match(a_string_including("application/json"))
      end

      it "document's other properties are still correct" do
        fiat = cars(:fiat)
        michael = users(:michael)
        document = documents(:fiat_title)
        patch document_url(document), params: new_attributes, headers: valid_headers, as: :json
        fiat_title = JSON.parse(response.body)
        fiat_title = JSON.parse(response.body)
        expect(fiat_title['date']).to be_nil
        expect(fiat_title['notes']).to be_nil
        expect(fiat_title['attachment']).to match(/http.*title-fiat-500\.gif/)
        expect(fiat_title['carId']).to eq fiat.id
        expect(fiat_title['carName']).to eq fiat.name
        expect(fiat_title['userId']).to eq michael.id
        expect(fiat_title['userName']).to eq michael.name
      end

      context "with invalid parameters" do
        it "renders a JSON response with errors for the document" do
          document = documents(:fiat_title)
          patch document_url(document), params: invalid_attributes, headers: valid_headers, as: :json
          expect(response).to have_http_status(:unprocessable_entity)
          expect(response.content_type).to match(a_string_including("application/json"))
        end
      end

    end

    describe "DELETE /destroy" do
      it "destroys the requested document" do
        document = Document.create! valid_attributes
        expect { delete document_url(document), headers: valid_headers, as: :json
        }.to change(Document, :count).by(-1)
      end
    end

  end


end
~
EOF
cat <<'EOF' | puravida spec/models/document_spec.rb ~
require 'rails_helper'

RSpec.describe Document, type: :model do
  fixtures :users, :cars, :maintenances, :documents
  let(:valid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: maintenances(:fiat_alignment).id
  }}
  let(:invalid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: -1
  }}

  it "is valid with valid attributes" do
    expect(Document.new(valid_attributes)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(Document.new(invalid_attributes)).to_not be_valid
  end
end
~
EOF
rspec

echo -e "\n\n🦄  Seeds\n\n"
cat <<'EOF' | puravida db/seeds.rb ~
user = User.create(name: "Michael Scott", email: "michaelscott@dundermifflin.com", admin: "true", password: "password")
user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/michael-scott.png"), filename: "michael-scott.png")
user.save!
user = User.create(name: "Jim Halpert", email: "jimhalpert@dundermifflin.com", admin: "false", password: "password")
user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/jim-halpert.png"), filename: "jim-halpert.png")
user.save!
user = User.create(name: "Pam Beesly", email: "pambeesly@dundermifflin.com", admin: "false", password: "password")
user.avatar.attach(io: URI.open("#{Rails.root}/app/assets/images/office-avatars/pam-beesly.png"), filename: "jim-halpert.png")
user.save!
car = Car.create(name: "Michael's Fiat 500", make: "Fiat", model: "500", trim: "Sport", color: "Yellow", body: "Hatchback", plate: "6XYK922", vin: "3C3CFFBR0CT382584", year: 2012, cost: "10235.00", purchase_vendor: "Ted Fleid", initial_mileage: 47361, purchase_date: Date.parse("20180606"), user_id: 1)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/fiat-500.jpg"), filename: "fiat-500.jpg")
car.save!
car = Car.create(name: "Michael's Honda Civic", make: "Honda", model: "Civic", trim: "Vp", color: "Blue", body: "Sedan", plate: "4HGJ708", vin: "2HGEJ6618XH589506", year: 1999, cost: "10352", purchase_vendor: "Howdy Honda", initial_mileage: 78032, purchase_date: Date.parse("20160713"), user_id: 1)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/honda-civic.jpg"), filename: "honda-civic.jpg")
car.save!
car = Car.create(name: "Jim's Hyundai Elantra", make: "Hyundai", model: "Elantra", trim: "GLS", color: "Black", body: "Sedan", plate: "8CEU662", vin: "KMHDU46D17U090264", year: 2007, cost: "15000.00", purchase_vendor: "Feit Hyundai", initial_mileage: 53032, purchase_date: Date.parse("20200115"), user_id: 2)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/hyundai-elantra.jpg"), filename: "hyundai-elantra.jpg")
car.save!
car = Car.create(name: "Jim's Nissan Leaf", make: "Nissan", model: "Leaf", trim: "SV", color: "Silver", body: "Hatchback", plate: "ABC123", vin: "1N4AZ1CP8LC310110", year: 2020, cost: "22590.00", purchase_vendor: "Carvana", initial_mileage: 21440, purchase_date: Date.parse("20230429"), user_id: 2)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/nissan-leaf.jpg"), filename: "nissan-leaf.jpg")
car.save!
car = Car.create(name: "Pam's Scion Xb", make: "Scion", model: "Xb", trim: "Base / Parklan Edition", color: "Gray", body: "Wagon", plate: "7MBE060", vin: "JTLZE4FE0FJ074884", year: 2015, cost: "25867.00", purchase_vendor: "Craigslist", initial_mileage: 35631, purchase_date: Date.parse("20201109"), user_id: 3)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/scion.jpg"), filename: "scion.jpg")
car.save!
car = Car.create(name: "Pam's Toyota Camry", make: "Toyota", model: "Camry", trim: "LE", color: "Black", body: "Sedan", plate: "HDH1439", vin: "4T1BE46K49U358097", year: 2009, cost: "7300", purchase_vendor: "Tanne Toyota", initial_mileage: 134087, purchase_date: Date.parse("20100513"), user_id: 3)
car.image.attach(io: URI.open("#{Rails.root}/app/assets/images/cars/toyota-camry.jpg"), filename: "toyota-camry.jpg")
car.save!
maintenance = Maintenance.create(date: Date.parse("20200713"), description: "Alignment", vendor: "Pep Boys", cost: "350.00", car_id: 1)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-alignment-1.jpg"), filename: "fiat-alignment-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-alignment-2.jpg"), filename: "fiat-alignment-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20210812"), description: "Oil Change", vendor: "Jiffy Lube", cost: "78.00", car_id: 1)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-oil-change-1.jpg"), filename: "fiat-oil-change-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-oil-change-2.jpg"), filename: "fiat-oil-change-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20170123"), description: "Brake Repair", vendor: "WalMart", cost: "400.00", car_id: 2)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-brake-repair-1.jpg"), filename: "civic-brake-repair-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-brake-repair-2.jpg"), filename: "civic-brake-repair-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20200311"), description: "Tire Rotation", vendor: "Goodyear", cost: "105.00", car_id: 2)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-tire-rotation-1.jpg"), filename: "civic-tire-rotation-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-tire-rotation-2.jpg"), filename: "civic-tire-rotation-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20200111"), description: "New Tires", vendor: "Scott's", cost: "812.00", car_id: 3)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-new-tires-1.jpg"), filename: "elantra-new-tires-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-new-tires-2.jpg"), filename: "elantra-new-tires-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20230627"), description: "Repaired Body Dents", vendor: "Tenede Auto", cost: "1343.00", car_id: 3)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-repaired-body-1.jpg"), filename: "elantra-repaired-body-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-repaired-body-2.jpg"), filename: "elantra-repaired-body-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20150614"), description: "Windshield Replacement", vendor: "45th St. Car Repair", cost: "800.00", car_id: 4)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-windshield-replacement-1.jpg"), filename: "leaf-windshield-replacement-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-windshield-replacement-2.jpg"), filename: "leaf-windshield-replacement-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20170811"), description: "New Spark Plugs", vendor: "Jim & Tony's Automotive Service", cost: "5.00", car_id: 4)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-new-spark-plugs-1.jpg"), filename: "leaf-new-spark-plugs-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-new-spark-plugs-2.jpg"), filename: "leaf-new-spark-plugs-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20200909"), description: "Engine Overhaul", vendor: "Auto Stoppe", cost: "5932.00", car_id: 5)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-engine-overhaul-1.jpg"), filename: "scion-engine-overhaul-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-engine-overhaul-2.jpg"), filename: "scion-engine-overhaul-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20201030"), description: "50,000 Mile Maintenance", vendor: "Dealership", cost: "0", car_id: 5)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-5k-mile-maintenance-1.jpg"), filename: "scion-5k-mile-maintenance-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-5k-mile-maintenance-2.jpg"), filename: "scion-5k-mile-maintenance-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20220903"), description: "Fuel Line Replacement", vendor: "Foreign Auto Austin", cost: "37.00", car_id: 6)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-fuel-line-1.jpg"), filename: "camry-fuel-line-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-fuel-line-2.jpg"), filename: "camry-fuel-line-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse("20230601"), description: "Replaced Radiator", vendor: "Blan's Auto Repair", cost: "400.00", car_id: 6)
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-replaced-radiator-1.jpg"), filename: "camry-replaced-radiator-1.jpg")
maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-replaced-radiator-2.jpg"), filename: "camry-replaced-radiator-2.jpg")
maintenance.save!
document = Document.create(name: "title-fiat-500", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 1)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-fiat-500.gif"), filename: "title-fiat-500.gif")
document = Document.create(name: "contract-fiat-500", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 1)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-fiat-500.webp"), filename: "contract-fiat-500.webp")
document = Document.create(name: "title-honda-civic", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 2)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-honda-civic.png"), filename: "title-honda-civic.png")
document = Document.create(name: "contract-honda-civic", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 2)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-honda-civic.png"), filename: "contract-honda-civic.png")
document = Document.create(name: "title-hyundai-elantra", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 3)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-hyundai-elantra.pdf"), filename: "title-hyundai-elantra.pdf")
document = Document.create(name: "contract-hyundai-elantra", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 3)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-hyundai-elantra.jpg"), filename: "contract-hyundai-elantra.jpg")
document = Document.create(name: "title-nissan-leaf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 4)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-nissan-leaf.png"), filename: "title-nissan-leaf.png")
document = Document.create(name: "contract-nissan-leaf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 4)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-nissan-leaf.png"), filename: "contract-nissan-leaf.png")
document = Document.create(name: "title-scion", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 5)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-scion.jpg"), filename: "title-scion.jpg")
document = Document.create(name: "contract-scion", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 5)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-scion.pdf"), filename: "contract-scion.pdf")
document = Document.create(name: "title-toyota-camry", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 6)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/titles/title-toyota-camry.jpg"), filename: "title-toyota-camry.jpg")
document = Document.create(name: "contract-toyota-camry", date: Date.parse("20200909"), notes: "notes", documentable_type: "Car",documentable_id: 6)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/car-documents/contracts/contract-toyota-camry.jpg"), filename: "contract-toyota-camry.jpg")
document = Document.create(name: "fiat-alignment-1.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 1)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/fiat-alignment-1.png"), filename: "fiat-alignment-1.png")
document = Document.create(name: "fiat-alignment-2.txt", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 1)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/fiat-alignment-2.txt"), filename: "fiat-alignment-2.txt")
document = Document.create(name: "fiat-oil-change-1.txt", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 2)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/fiat-oil-change-1.txt"), filename: "fiat-oil-change-1.txt")
document = Document.create(name: "fiat-oil-change-2.txt", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 2)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/fiat-oil-change-1.txt"), filename: "fiat-oil-change-1.txt")
document = Document.create(name: "civic-brake-repair-1.jpg", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 3)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/civic-brake-repair-1.jpg"), filename: "civic-brake-repair-1.jpg")
document = Document.create(name: "civic-brake-repair-2.pdf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 3)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/civic-brake-repair-2.pdf"), filename: "civic-brake-repair-2.pdf")
document = Document.create(name: "civic-tire-rotation-1.pdf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 4)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/civic-tire-rotation-1.pdf"), filename: "civic-tire-rotation-1.pdf")
document = Document.create(name: "civic-tire-rotation-2.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 4)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/civic-tire-rotation-2.png"), filename: "civic-tire-rotation-2.png")
document = Document.create(name: "elantra-new-tires-1.pdf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 5)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/elantra-new-tires-1.pdf"), filename: "elantra-new-tires-1.pdf")
document = Document.create(name: "elantra-new-tires-2.pdf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 5)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/elantra-new-tires-2.pdf"), filename: "elantra-new-tires-2.pdf")
document = Document.create(name: "elantra-repaired-body-1.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 6)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/elantra-repaired-body-1.png"), filename: "elantra-repaired-body-1.png")
document = Document.create(name: "elantra-repaired-body-2.pdf", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 6)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/elantra-repaired-body-2.pdf"), filename: "elantra-repaired-body-2.pdf")
document = Document.create(name: "leaf-windshield-replacement-1.webp", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 7)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/leaf-windshield-replacement-1.webp"), filename: "leaf-windshield-replacement-1.webp")
document = Document.create(name: "leaf-windshield-replacement-2.webp", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 7)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/leaf-windshield-replacement-2.webp"), filename: "leaf-windshield-replacement-2.webp")
document = Document.create(name: "leaf-new-spark-plugs-1.txt", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 8)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/leaf-new-spark-plugs-1.txt"), filename: "leaf-new-spark-plugs-1.txt")
document = Document.create(name: "leaf-new-spark-plugs-2.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 8)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/leaf-new-spark-plugs-2.png"), filename: "leaf-new-spark-plugs-2.png")
document = Document.create(name: "scion-engine-overhaul-1.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 9)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/scion-engine-overhaul-1.png"), filename: "scion-engine-overhaul-1.png")
document = Document.create(name: "scion-engine-overhaul-2.jpg", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 9)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/scion-engine-overhaul-2.jpg"), filename: "scion-engine-overhaul-2.jpg")
document = Document.create(name: "scion-5k-mile-maintenance-1.jpg", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 10)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/scion-5k-mile-maintenance-1.jpg"), filename: "scion-5k-mile-maintenance-1.jpg")
document = Document.create(name: "scion-5k-mile-maintenance-2.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 10)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/scion-5k-mile-maintenance-2.png"), filename: "scion-5k-mile-maintenance-2.png")
document = Document.create(name: "camry-fuel-line-1.txt", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 11)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/camry-fuel-line-1.txt"), filename: "camry-fuel-line-1.txt")
document = Document.create(name: "camry-fuel-line-2.webp", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 11)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/camry-fuel-line-2.webp"), filename: "camry-fuel-line-2.webp")
document = Document.create(name: "camry-replaced-radiator-1.png", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 12)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/camry-replaced-radiator-1.png"), filename: "camry-replaced-radiator-1.png")
document = Document.create(name: "camry-replaced-radiator-2.webp", date: Date.parse("20200909"), notes: "notes", documentable_type: "Maintenance",documentable_id: 12)
document.attachment.attach(io: URI.open("#{Rails.root}/app/assets/images/documents/maintenance-documents/camry-replaced-radiator-2.webp"), filename: "camry-replaced-radiator-2.webp")
~
EOF
rails db:seed
rm -rf spec/factories
rm -rf spec/routing

echo -e "\n\n🦄 FRONTEND\n\n"

echo -e "\n\n🦄 Setup\n\n"

cd ~/Desktop
npx create-nuxt-app front
cd front
npm install @picocss/pico @nuxtjs/auth@4.5.1 @fortawesome/fontawesome-svg-core @fortawesome/free-solid-svg-icons @fortawesome/free-brands-svg-icons @fortawesome/vue-fontawesome@latest-2
npm install --save-dev sass sass-loader@10
cat <<'EOF' | puravida assets/scss/main.scss ~
@import "node_modules/@picocss/pico/scss/pico.scss";

// Pico overrides 
// $primary-500: #e91e63;

h1 {
  margin: 4rem 0
}

.no-margin {
  margin: 0
}

.small-bottom-margin {
  margin: 0 0 0.5rem
}

.big-bottom-margin {
  margin: 0 0 8rem
}

.half-width {
  margin: 0 0 4rem;
  width: 50%;
}

nav img {
  width: 40px;
  border-radius: 50%;
  border: 3px solid var(--primary);
}

article img {
  margin-bottom: var(--typography-spacing-vertical);
  width: 250px;
}

ul.features { 
  margin: 0 0 2.5rem 1rem;
  li {
    margin: 0;
    padding: 0;
  }
}

.aligned-columns {
  margin: 0 0 2rem;
  p {
    margin: 0;
    span {
      margin: 0 0.5rem 0 0;
      display: inline-block;
      width: 8rem;
      text-align: right;
      font-weight: bold;
    }
  }
}
~
EOF
cat <<'EOF' | puravida nuxt.config.js ~
let development = process.env.NODE_ENV !== 'production'
export default {
  ssr: false,
  head: { title: 'front', htmlAttrs: { lang: 'en' },
    meta: [ { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: '' },
      { name: 'format-detection', content: 'telephone=no' }
    ], link: [{ rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }]
  },
  css: ['@fortawesome/fontawesome-svg-core/styles.css','@/assets/scss/main.scss'],
  plugins: [ '~/plugins/fontawesome.js' ],
  components: true,
  buildModules: [],
  router: { middleware: ['auth'] },
  modules: ['@nuxtjs/axios', '@nuxtjs/auth'],
  axios: { baseURL: development ? 'http://localhost:3000' : 'https://ruxtmin-back.fly.dev/' },
  server: { port: development ? 3001 : 3000 },
  auth: {
    redirect: { login: '/' },
    strategies: {
      local: {
        endpoints: {
          login: { url: 'login', method: 'post', propertyName: 'data' },
          logout: false,
          user: { url: 'me', method: 'get', propertyName: 'data' }
        }
      }
    }
  }
}
~
EOF
cat <<'EOF' | puravida middleware/adminOnly.js ~
export default function ({ store, redirect }) {
  if (!store.state.auth.user.admin) {
    return redirect('/')
  }
}
~
EOF
cat <<'EOF' | puravida middleware/currentOrAdmin-showEdit.js ~
import { mapGetters } from 'vuex'
export default function ({ route, store, redirect }) {
  const { isAdmin, loggedInUser } = store.getters
  const url = route.fullPath;
  const splitPath = url.split('/')
  let elemId = null
  let isElemUsers = false
  let isCar = false;
  let isMaintenance = false;
  let isDocument = false;
  let isUser = false;
  const userCars = loggedInUser.car_ids
  const userMaintenances = loggedInUser.maintenances_ids
  const userDocuments = loggedInUser.documents_ids

  if (url.includes("document")) {
    isDocument = true
  } else if (url.includes("maintenance")) { 
    isMaintenance = true
  } else if (url.includes("car")) {
    isCar = true
  } else if (url.includes("users")) {
    isUser = true
  }

  if (isEditPage(url)) {
    elemId = parseInt(splitPath[splitPath.length-2])
  } else if (isShowPage(url)) {
    elemId = parseInt(splitPath[splitPath.length-1])
  }
  
  if (isCar) {
    isElemUsers = userCars.includes(elemId) ? true : false
  } else if (isMaintenance) {
    isElemUsers = userMaintenances.includes(elemId) ? true : false
  } else if (isDocument) {
    isElemUsers = userDocuments.includes(elemId) ? true : false
  } else if (isUser) {
    isElemUsers = loggedInUser.id === elemId ? true : false
  }

  if (!isAdmin && !isElemUsers) {
    return redirect('/')
  }
}

function isEditPage(url) {
  return url.includes("edit") ? true : false
}

function isShowPage(url) {
  const splitUrl = url.split('/')
  return (!isNaN(splitUrl[splitUrl.length-1]) && !isEditPage(url)) ? true : false
}
~
EOF
cat <<'EOF' | puravida middleware/currentOrAdmin-index.js ~
export default function ({ route, store, redirect }) {
  const { isAdmin, loggedInUser } = store.getters
  const query = route.query
  const isAdminRequest = query['admin'] ? true : false
  const isUserIdRequest = query['user_id'] ? true : false
  const isQueryEmpty = Object.keys(query).length === 0 ? true : false
  const userIdRequestButNotAdmin = isUserIdRequest && !isAdmin
  const requested_user_id = parseInt(query['user_id'])
  const actual_user_id = loggedInUser.id
  const allowedAccess = requested_user_id === actual_user_id ? true : false

  if ((isAdminRequest || isQueryEmpty) && !isAdmin) {
    return redirect('/')
  } else if (userIdRequestButNotAdmin && !allowedAccess) {
    return redirect('/cars?user_id=' + loggedInUser.id)
  }
}
~
EOF
cat <<'EOF' | puravida plugins/fontawesome.js ~
import Vue from 'vue'
import { library, config } from '@fortawesome/fontawesome-svg-core'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
import { fas } from '@fortawesome/free-solid-svg-icons'

config.autoAddCss = false
library.add(fas)
Vue.component('font-awesome-icon', FontAwesomeIcon)
~
EOF
rm -f components/*.vue
echo -e "\n\n🦄 New User Page\n\n"
cat <<'EOF' | puravida components/user/Form.vue ~
<template>
  <section>
    <h1 v-if="editNewOrSignup === 'edit'">Edit User</h1>
    <h1 v-else-if="editNewOrSignup === 'new'">Add User</h1>
    <h1 v-else-if="editNewOrSignup === 'sign-up'">Sign Up</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editNewOrSignup === 'edit'">id: {{ $route.params.id }}</p>
        <p>Name: </p><input v-model="name">
        <p>Email: </p><input v-model="email">
        <p class="no-margin">Avatar: </p>
        <img v-if="!hideAvatar && editNewOrSignup === 'edit'" :src="avatar" />    
        <input type="file" ref="inputFile" @change=uploadAvatar()>
        <p v-if="editNewOrSignup !== 'edit'">Password: </p>
        <input v-if="editNewOrSignup !== 'edit'" type="password" v-model="password">
        <button v-if="editNewOrSignup !== 'edit'" @click.prevent=createUser>Create User</button>
        <button v-else-if="editNewOrSignup == 'edit'" @click.prevent=editUser>Edit User</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  data () {
    return {
      name: "",
      email: "",
      avatar: "",
      password: "",
      editNewOrSignup: "",
      hideAvatar: false
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editNewOrSignup = splitPath[splitPath.length-1]
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editNewOrSignup = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const user = await this.$axios.$get(`users/${this.$route.params.id}`)
      this.name = user.name
      this.email = user.email,
      this.avatar = user.avatar  
    }
  },
  methods: {
    uploadAvatar: function() {
      this.avatar = this.$refs.inputFile.files[0]
      this.hideAvatar = true
    },
    createUser: function() {
      const params = {
        'name': this.name,
        'email': this.email,
        'avatar': this.avatar,
        'password': this.password,
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('users', payload)
        .then(() => {
          this.$auth.loginWith('local', {
            data: {
            email: this.email,
            password: this.password
            },
          })
          .then(() => {
            const userId = this.$auth.$state.user.id
            this.$router.push(`/users/${userId}`)
          })
        })
    },
    editUser: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        params = { 'name': this.name, 'email': this.email }
      } else {
        params = { 'name': this.name, 'email': this.email, 'avatar': this.avatar }
      }
    
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/users/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/users/${this.$route.params.id}`)
        })
    },
  }
}
</script>
~
EOF
cat <<'EOF' | puravida pages/users/new.vue ~
<template>
  <main class="container">
    <UserForm />
  </main>
</template>
~
EOF
echo -e "\n\n🦄 Users Page\n\n"
cat <<'EOF' | puravida components/user/Card.vue ~
<template>
  <article>
    <h2>
      <NuxtLink :to="`/users/${user.id}`">{{ user.name }}</NuxtLink> 
      <NuxtLink :to="`/users/${user.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteUser(user.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ user.id }}</p>
    <p>email: {{ user.email }}</p>
    <p v-if="user.avatar !== null" class="no-margin">avatar:</p>
    <img v-if="user.avatar !== null" :src="user.avatar" />
    <p v-if="isAdmin">admin: {{ user.admin }}</p>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'UserCard',
  computed: { ...mapGetters(['isAdmin']) },
  props: {
    user: {
      type: Object,
      default: () => ({}),
    },
    users: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadAvatar: function() {
      this.avatar = this.$refs.inputFile.files[0];
    },
    deleteUser: function(id) {
      this.$axios.$delete(`users/${id}`)
      const index = this.users.findIndex((i) => { return i.id === id })
      this.users.splice(index, 1);
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida components/user/Set.vue ~
<template>
  <section>
    <div v-for="user in users" :key="user.id">
      <UserCard :user="user" :users="users" />
    </div>
  </section>
</template>

<script>
export default {
  data: () => ({
    users: []
  }),
  async fetch() {
    this.users = await this.$axios.$get('users')
  }
}
</script>
~
EOF

cat <<'EOF' | puravida pages/users/index.vue ~
<template>
  <main class="container">
    <h1>Users</h1>
    <NuxtLink to="/users/new" role="button">Add User</NuxtLink>
    <UserSet />
  </main>
</template>

<script>
export default { middleware: 'adminOnly' }
</script>
~
EOF

echo -e "\n\n🦄 User Page\n\n"
cat <<'EOF' | puravida pages/users/_id/index.vue ~
<template>
  <main class="container">
    <section>
      <UserCard :user="user" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ user: {} }),
  async fetch() { this.user = await this.$axios.$get(`users/${this.$route.params.id}`) },
  methods: {
    uploadAvatar: function() { this.avatar = this.$refs.inputFile.files[0] },
    deleteUser: function(id) {
      this.$axios.$delete(`users/${this.$route.params.id}`)
      this.$router.push('/users')
    }
  }
}
</script>
~
EOF

echo -e "\n\n🦄 User Edit Page\n\n"
cat <<'EOF' | puravida pages/users/_id/edit.vue ~
<template>
  <main class="container">
    <UserForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
~
EOF


echo -e "\n\n🦄 Cars (frontend)\n\n"
cat <<'EOF' | puravida components/car/Card.vue ~
<template>
  <article>
    <h2>
      <NuxtLink :to="`/cars/${car.id}`">{{ car.name }}</NuxtLink> 
      <NuxtLink :to="`/cars/${car.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteCar(car.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ car.id }}</p>
    <p v-if="car.image !== null" class="no-margin">image:</p>
    <img v-if="car.image !== null" :src="car.image" />
    <p>year: {{ car.year }}</p>
    <p>make: {{ car.make }}</p>
    <p>model: {{ car.model }}</p>
    <p>trim: {{ car.trim }}</p>
    <p>body: {{ car.body }}</p>
    <p>color: {{ car.color }}</p>
    <p>plate: {{ car.plate }}</p>
    <p>vin: {{ car.vin }}</p>
    <p>cost: {{ car.cost }}</p>
    <p>initial_mileage: {{ car.initial_mileage }}</p>
    <p>purchase_date: {{ car.purchase_date }}</p>
    <p>purchase_vendor: {{ car.purchase_vendor }}</p>
    <h4 v-if="car.maintenances !== null">Maintenances</h4>
    <ul v-if="car.maintenances !== null">
      <li v-for="maintenance in car.maintenances" :key="maintenance.id">
        <NuxtLink :to="`/maintenances/${maintenance.id}`">{{ maintenance.description }}</NuxtLink>
      </li>
    </ul>
    <h4 v-if="car.documents !== null">Documents</h4>
    <ul v-if="car.documents !== null">
      <li v-for="document in car.documents" :key="document.id">
        <NuxtLink :to="`/documents/${document.id}`">{{ document.name }}</NuxtLink>
      </li>
    </ul>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'CarCard',
  computed: { ...mapGetters(['isAdmin']) },
  props: {
    car: {
      type: Object,
      default: () => ({}),
    },
    cars: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteCar: function(id) {
      this.$axios.$delete(`cars/${id}`)
      const index = this.cars.findIndex((i) => { return i.id === id })
      this.cars.splice(index, 1);
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida components/car/Set.vue ~
<template>
  <section>
    <div v-for="car in cars" :key="car.id">
      <CarCard :car="car" :cars="cars" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    cars: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.cars = await this.$axios.$get('cars')
    } else if (idQuery) {
      this.cars = await this.$axios.$get('cars', {
        params: { user_id: idQuery }
      })
    } else {
      this.cars = await this.$axios.$get('cars', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
~
EOF

cat <<'EOF' | puravida components/car/Form.vue ~
<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Car</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Car</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Name: </p><input v-model="name">
        <p class="no-margin">Image: </p>
        <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
        <input type="file" ref="inputFile" @change=uploadImage()>
        <p>year: </p><input v-model="year">
        <p>make: </p><input v-model="make">
        <p>model: </p><input v-model="model">
        <p>trim: </p><input v-model="trim">
        <p>body: </p><input v-model="body">
        <p>color: </p><input v-model="color">
        <p>plate: </p><input v-model="plate">
        <p>vin: </p><input v-model="vin">
        <p>cost: </p><input v-model="cost">
        <p>initial_mileage: </p><input v-model="initial_mileage">
        <p>purchase_date: </p><input v-model="purchase_date">
        <p>purchase_vendor: </p><input v-model="purchase_vendor">
        <button v-if="editOrNew !== 'edit'" @click.prevent=createCar>Create Car</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editCar>Edit Car</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  data () {
    return {
      name: "",
      description: "",
      image: "",
      year: "",
      make: "",
      model: "",
      trim: "",
      body: "",
      color: "",
      plate: "",
      vin: "",
      cost: "",
      initial_mileage: "",
      purchase_date: "",
      purchase_vendor: "",
      editOrNew: "",
      hideImage: false
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const car = await this.$axios.$get(`cars/${this.$route.params.id}`)
      this.name = car.name
      this.image = car.image
      this.year = car.year
      this.make = car.make
      this.model = car.model
      this.trim = car.trim
      this.body = car.body
      this.color = car.color
      this.plate = car.plate
      this.vin = car.vin
      this.cost = car.cost
      this.initial_mileage = car.initial_mileage
      this.purchase_date = car.purchase_date
      this.purchase_vendor = car.purchase_vendor
    }
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0]
      this.hideImage = true
    },
    createCar: function() {
      const userId = this.$auth.$state.user.id
      const params = {
        'name': this.name,
        'image': this.image,
        'year': this.year,
        'make': this.make,
        'model': this.model,
        'trim': this.trim,
        'body': this.body,
        'color': this.color,
        'plate': this.plate,
        'vin': this.vin,
        'cost': this.cost,
        'initial_mileage': this.initial_mileage,
        'purchase_date': this.purchase_date,
        'purchase_vendor': this.purchase_vendor,
        'user_id': userId
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('cars', payload)
        .then((res) => {
          const carId = res.id
          this.$router.push(`/cars/${carId}`)
        })
    },
    editCar: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        params = { 'name': this.name, 'description': this.description }
      } else {
        params = { 'name': this.name, 'description': this.description, 'image': this.image }
      }
    
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/cars/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/cars/${this.$route.params.id}`)
        })
    },
  }
}
</script>
~
EOF


cat <<'EOF' | puravida pages/cars/index.vue ~
<template>
  <main class="container">
    <h1>Cars</h1>
    <NuxtLink to="/cars/new" role="button">Add Car</NuxtLink>
    <CarSet />
  </main>
</template>
<script>
export default { middleware: 'currentOrAdmin-index' }
</script>
~
EOF

cat <<'EOF' | puravida pages/cars/new.vue ~
<template>
  <main class="container">
    <CarForm />
  </main>
</template>
~
EOF

cat <<'EOF' | puravida pages/cars/_id/index.vue ~
<template>
  <main class="container">
    <section>
      <CarCard :car="car" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ car: {} }),
  async fetch() { this.car = await this.$axios.$get(`cars/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteCar: function(id) {
      this.$axios.$delete(`cars/${this.$route.params.id}`)
      this.$router.push('/cars')
    }
  }
}
</script>
~
EOF

cat <<'EOF' | puravida pages/cars/_id/edit.vue ~
<template>
  <main class="container">
    <CarForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
~
EOF

echo -e "\n\n🦄 Maintenances (frontend)\n\n"
cat <<'EOF' | puravida components/maintenance/Card.vue ~
<template>
  <article>
    <h2>
      <NuxtLink :to="`/maintenances/${maintenance.id}`">{{ maintenance.description }}</NuxtLink> 
      <NuxtLink :to="`/maintenances/${maintenance.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteCar(maintenance.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ maintenance.id }}</p>
    <p>date: {{ maintenance.date }}</p>
    <p>description: {{ maintenance.description }}</p>
    <p>vendor: {{ maintenance.vendor }}</p>
    <p>cost: {{ maintenance.cost }}</p>
    <p v-if="maintenance.images !== null" class="no-margin">images:</p>
    <div v-if="maintenance.images !== null" :src="maintenance.image">
      <div v-for="image in maintenance.images" :key="image">
        <img :src="image" />
      </div>
    </div>
    <p>car: <NuxtLink :to="`/cars/${maintenance.carId}`">{{ maintenance.carName }}</NuxtLink></p>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'MaintenanceCard',
  computed: { ...mapGetters(['isAdmin']) },
  props: {
    maintenance: {
      type: Object,
      default: () => ({}),
    },
    maintenances: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteMaintenance: function(id) {
      this.$axios.$delete(`maintenances/${id}`)
      const index = this.maintenances.findIndex((i) => { return i.id === id })
      this.maintenances.splice(index, 1);
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida components/maintenance/Set.vue ~
<template>
  <section>
    <div v-for="maintenance in maintenances" :key="maintenance.id">
      <MaintenanceCard :maintenance="maintenance" :maintenances= "maintenances" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    maintenances: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.maintenances = await this.$axios.$get('maintenances')
    } else if (idQuery) {
      this.maintenances = await this.$axios.$get('maintenances', {
        params: { user_id: idQuery }
      })
    } else {
      this.maintenances = await this.$axios.$get('maintenances', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida components/maintenance/Form.vue ~
<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Maintenance</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Maintenance</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Date: </p><input v-model="date">
        <p>Description: </p><input v-model="description">
        <p>Vendor: </p><input v-model="vendor">
        <p>Cost: </p><input v-model="cost">
        <p class="no-margin">Image: </p>
        <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
        <input type="file" ref="inputFile" @change=uploadImage()>
        <p>Car Id: {{ carId }}</p>
        <select v-if="editOrNew === 'new'" name="car" @change="selectCar($event)">
          <option value=""></option>
          <option v-for="car in cars" :key="car.id" :value="car.id">{{ car.name }} - {{ car.description }}</option>
        </select>
        <button v-if="editOrNew !== 'edit'" @click.prevent=createMaintenance>Create Maintenance</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editMaintenance>Edit Maintenance</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  data () {
    return {
      date: "",
      description: "",
      vendor: "",
      cost: "",
      image: "",
      editOrNew: "",
      hideImage: false,
      cars: [],
      carId: ""
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const maintenance = await this.$axios.$get(`maintenances/${this.$route.params.id}`)
      console.log(maintenance)
      this.date = maintenance.date
      this.description = maintenance.description,
      this.vendor = maintenance.vendor
      this.cost = maintenance.cost
      this.image = maintenance.image
      this.carId = maintenance.carId 
    }
    if (this.editOrNew == 'new') {
      this.cars = await this.$axios.$get('/cars', {
        params: { user_id: this.$auth.$state.user.id }
      })
    }
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0]
      this.hideImage = true
    },
    createMaintenance: function() {
      const params = {
        'date': this.date,
        'description': this.description,
        'vendor': this.vendor,
        'cost': this.cost,
        'image': this.image,
        'car_id': this.carId
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('maintenances', payload)
        .then((res) => {
          const maintenanceId = res.id
          this.$router.push(`/maintenances/${maintenanceId}`)
        })
    },
    editMaintenance: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        params = { 'name': this.name, 'date': this.date, 'description': this.description, 'vendor': this.vendor, 'cost': this.cost }
      } else {
        params = { 'name': this.name, 'date': this.date, 'description': this.description, 'vendor': this.vendor, 'cost': this.cost, 'image': this.image }
      } 
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/maintenances/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/maintenances/${this.$route.params.id}`)
        })
    },
    selectCar: function(event) {
      this.carId = event.target.value
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida pages/maintenances/index.vue ~
<template>
  <main class="container">
    <h1>Maintenances</h1>
    <NuxtLink to="/maintenances/new" role="button">Add Maintenance</NuxtLink>
    <MaintenanceSet />
  </main>
</template>
<script>
export default { middleware: 'currentOrAdmin-index' }
</script>
~
EOF
cat <<'EOF' | puravida pages/maintenances/new.vue ~
<template>
  <main class="container">
    <MaintenanceForm />
  </main>
</template>
~
EOF
cat <<'EOF' | puravida pages/maintenances/_id/index.vue ~
<template>
  <main class="container">
    <section>
      <MaintenanceCard :maintenance="maintenance" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ maintenance: {} }),
  async fetch() { this.maintenance = await this.$axios.$get(`maintenances/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteMaintenance: function(id) {
      this.$axios.$delete(`maintenances/${this.$route.params.id}`)
      this.$router.push('/maintenances')
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida pages/maintenances/_id/edit.vue ~
<template>
  <main class="container">
    <MaintenanceForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
~
EOF




echo -e "\n\n🦄 Documents (frontend)\n\n"
cat <<'EOF' | puravida components/document/Card.vue ~
<template>
  <article>
    <h2>
      <NuxtLink :to="`/documents/${document.id}`">{{ document.name }}</NuxtLink> 
      <NuxtLink :to="`/documents/${document.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteCar(document.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ document.id }}</p>
    <p>date: {{ document.date }}</p>
    <p>notes: {{ document.notes }}</p>
    <p>attachment: <a :href="document.attachment">{{ document.attachmentFile }}</a></p>
    <p v-if="document.hasOwnProperty('maintenanceDescription')">maintenance: <NuxtLink :to="`/maintenances/${document.maintenanceId}`">{{ document.maintenanceDescription }}</NuxtLink></p>
    <p>car: <NuxtLink :to="`/cars/${document.carId}`">{{ document.carName }}</NuxtLink></p>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'DocumentCard',
  props: {
    document: {
      type: Object,
      default: () => ({}),
    },
    documents: {
      type: Array,
      default: () => ([]),
    },
  },
  computed: { ...mapGetters(['isAdmin']) },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteDocument: function(id) {
      this.$axios.$delete(`documents/${id}`)
      const index = this.documents.findIndex((i) => { return i.id === id })
      this.documents.splice(index, 1);
    }
    
  }
}
</script>
~
EOF

cat <<'EOF' | puravida components/document/Set.vue ~
<template>
  <section>
    <div v-for="document in documents" :key="document.id">
      <DocumentCard :document="document" :documents= "documents" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    documents: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.documents = await this.$axios.$get('documents')
    } else if (idQuery) {
      this.documents = await this.$axios.$get('documents', {
        params: { user_id: idQuery }
      })
    } else {
      this.documents = await this.$axios.$get('documents', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
~
EOF

cat <<'EOF' | puravida components/document/Form.vue ~
<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Document</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Document</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Date: </p><input v-model="date">
        <p>Name: </p><input v-model="name">
        <p>Notes: </p><textarea v-model="notes"></textarea>
        <p class="no-margin">Image: </p>
        <!-- <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />     -->
        <input type="file" ref="inputFile" @change=uploadFile()>
        <p>Car or Maintenance Document: </p>
        <div>
          <input type="radio" id="car" value="Car" v-model="carOrMaintenance">
          <label for="car">Car</label>
        </div>
        <div>
          <input type="radio" id="maintenance" value="Maintenance" v-model="carOrMaintenance">
          <label for="maintenance">Maintenance</label>
        </div>
        <div v-if="editOrNew === 'new'">
          <select v-if="carOrMaintenance === 'Car'" name="Car" @change="selectCar($event)">
            <option value=""></option>
            <option v-for="car in cars" :key="car.id" :value="car.id">{{ car.name }}</option>
          </select>
          <select v-if="carOrMaintenance === 'Maintenance'" name="maintenance" @change="selectMaintenance($event)">
            <option value=""></option>
            <option v-for="maintenance in maintenances" :key="maintenance.id" :value="maintenance.id">{{ maintenance.description }} ({{ maintenance.carName }})</option>
          </select>
        </div>
        <button v-if="editOrNew !== 'edit'" @click.prevent=createDocument>Create Document</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editDocument>Edit Document</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  data () {
    return {
      date: "",
      name: "",
      notes: "",
      attachment: "",
      editOrNew: "",
      carOrMaintenance: "",
      userId: "",
      // hideImage: false,
      cars: [],
      carId: "",
      carIds: [],
      maintenances: [],
      maintenanceIds: "",
      maintenanceId: "",
      documents: [],
      documentIds: [],
      documentableId: ""
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
    this.getUserId()
    this.getCarsMaintsAndDocIds()
    
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const document = await this.$axios.$get(`documents/${this.$route.params.id}`)
      this.date = document.date
      this.name = document.name
      this.notes = document.notes
      this.description = document.description,
      this.attachment = document.image  
    }
    if (this.editOrNew == 'new') {
      this.maintenanceIds = 
      this.cars = await this.$axios.$get('/cars', { params: { user_id: this.$auth.$state.user.id } })
      this.maintenances = await this.$axios.$get('/maintenances', { params: { user_id: this.$auth.$state.user.id } })
    }
  },
  methods: {
    uploadFile: function() {
      this.attachment = this.$refs.inputFile.files[0]
      // this.hideImage = true
    },
    getUserId() {
      const userIdQuery = $nuxt.$route.query.user_id
      this.userId = userIdQuery ? userIdQuery : null
    },
    getCarsMaintsAndDocIds() {
      const user = this.$auth.user
      this.cars = user.cars
      this.maintenances = user.maintenances
      this.documents = user.documents
      console.log(this.maintenances)
    },
    createDocument: function() {
      const params = {
        'date': this.date,
        'name': this.name,
        'notes': this.notes,
        // 'attachment': this.attachment,
        'documentable_type': this.carOrMaintenance,
        'documentable_id': parseInt(this.documentableId)
      }
      console.log("params")
      console.log(params)
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('documents', payload)
        .then((res) => {
          const documentId = res.id
          this.$router.push(`/documents/${documentId}`)
        })
    },
    editDocument: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        params = { 'date': this.date, 'name': this.name, 'notes': this.notes, 'description': this.description }
      } else {
        params = { 'date': this.date, 'name': this.name, 'notes': this.notes, 'description': this.description, 'image': this.image }
      } 
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/documents/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/documents/${this.$route.params.id}`)
        })
    },
    selectCar: function(event) {
      this.carId = event.target.value
      this.documentableId = event.target.value
    },
    selectMaintenance: function(event) {
      this.maintenanceId = event.target.value
      this.documentableId = event.target.value
    }
  }
}
</script>
~
EOF

cat <<'EOF' | puravida pages/documents/index.vue ~
<template>
  <main class="container">
    <h1>Documents</h1>
    <NuxtLink :to="`${newDocUrl}`" role="button">Add Document</NuxtLink>
    <DocumentSet />
  </main>
</template>
<script>
  export default { 
    middleware: 'currentOrAdmin-index',
    data () {
      return {
        newDocUrl: ""
      }
    },
    mounted() {
      this.newDocUrl = this.getNewDocUrl()
    },
    methods: {
      getNewDocUrl: () => {
        const url = "/documents/new"
        let query = ""
        if ($nuxt.$route.query && $nuxt.$route.query.user_id) {
          query = `?user_id=${$nuxt.$route.query.user_id}`
        }
        return url + query
      }
    }
  }
</script>
~
EOF

cat <<'EOF' | puravida pages/documents/new.vue ~
<template>
  <main class="container">
    <DocumentForm />
  </main>
</template>
~
EOF

cat <<'EOF' | puravida pages/documents/_id/index.vue ~
<template>
  <main class="container">
    <section>
      <DocumentCard :document="document" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ document: {} }),
  async fetch() { this.document = await this.$axios.$get(`documents/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteDocument: function(id) {
      this.$axios.$delete(`documents/${this.$route.params.id}`)
      this.$router.push('/documents')
    }
  }
}
</script>
~
EOF

cat <<'EOF' | puravida pages/documents/_id/edit.vue ~
<template>
  <main class="container">
    <DocumentForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
~
EOF



echo -e "\n\n🦄 Nav\n\n"
cat <<'EOF' | puravida components/nav/Brand.vue ~
<template>
  <span>
    <font-awesome-icon icon="laptop-code" /> Ruxtmin
  </span>
</template>
~
EOF
cat <<'EOF' | puravida components/nav/Default.vue ~
<template>
  <nav class="top-nav container-fluid">
    <ul><li><strong><NuxtLink to="/"><NavBrand /></NuxtLink></strong></li></ul>
    <input id="menu-toggle" type="checkbox" />
    <label class='menu-button-container' for="menu-toggle">
      <div class='menu-button'></div>
    </label>
    <ul class="menu">
      <li v-if="!isAuthenticated"><strong><NuxtLink to="/log-in">Log In</NuxtLink></strong></li>
      <li v-if="!isAuthenticated"><strong><NuxtLink to="/sign-up">Sign Up</NuxtLink></strong></li>
      <li v-if="isAuthenticated"><strong><NuxtLink :to="`/cars?user_id=${loggedInUser.id}`">Cars</NuxtLink></strong></li>
      <li v-if="isAuthenticated"><strong><NuxtLink :to="`/maintenances?user_id=${loggedInUser.id}`">Maintenances</NuxtLink></strong></li>
      <li v-if="isAuthenticated"><strong><NuxtLink :to="`/documents?user_id=${loggedInUser.id}`">Documents</NuxtLink></strong></li>
      <li v-if="isAdmin"><strong><NuxtLink to="/admin">Admin</NuxtLink></strong></li>
      <li v-if="isAuthenticated" class='dropdown'>
        <details role="list" dir="rtl">
          <summary class='summary' aria-haspopup="listbox" role="link">
            <img v-if="loggedInUser.avatar" :src="loggedInUser.avatar" />
            <font-awesome-icon v-else icon="circle-user" />
          </summary>
          <ul role="listbox">
            <li><NuxtLink :to="`/users/${loggedInUser.id}`">Profile</NuxtLink></li>
            <li><NuxtLink :to="`/users/${loggedInUser.id}/edit`">Settings</NuxtLink></li>
            <li><a @click="logOut">Log Out</a></li>
          </ul>
        </details>
      </li>
      <!-- <li v-if="isAuthenticated"><strong><NuxtLink :to="`/users/${loggedInUser.id}`">Settings</NuxtLink></strong></li> -->
      <li class="logout-desktop" v-if="isAuthenticated"><strong><a @click="logOut">Log Out</a></strong></li>
    </ul>
  </nav>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  methods: { logOut() { this.$auth.logout() } }
}
</script>

<style lang="sass" scoped>
// css-only responsive nav
// from https://codepen.io/alvarotrigo/pen/MWEJEWG (accessed 10/16/23, modified slightly)

h2 
  vertical-align: center
  text-align: center

html, body 
  margin: 0
  height: 100%

.top-nav 
  height: 50px

.top-nav > ul 
  margin-top: 15px

.menu 
  display: flex
  flex-direction: row
  list-style-type: none
  margin: 0
  padding: 0

[type="checkbox"] ~ label.menu-button-container 
  display: none
  height: 100%
  width: 30px
  cursor: pointer
  flex-direction: column
  justify-content: center
  align-items: center

#menu-toggle 
  display: none

.menu-button,
.menu-button::before,
.menu-button::after 
  display: block
  background-color: #000
  position: absolute
  height: 4px
  width: 30px
  transition: transform 400ms cubic-bezier(0.23, 1, 0.32, 1)
  border-radius: 2px

.menu-button::before 
  content: ''
  margin-top: -8px

.menu-button::after 
  content: ''
  margin-top: 8px

#menu-toggle:checked + .menu-button-container .menu-button::before 
  margin-top: 0px
  transform: rotate(405deg)

#menu-toggle:checked + .menu-button-container .menu-button 
  background: rgba(255, 255, 255, 0)

#menu-toggle:checked + .menu-button-container .menu-button::after 
  margin-top: 0px
  transform: rotate(-405deg)

.menu 
  > li 
    overflow: visible

  > li.dropdown
    background: none

    .summary
      margin: 0
      padding: 1rem 0
      font-size: 1.5rem

      &:focus
        color: var(--color)
        background: none

      &:after
        display: none

    ul
      padding-top: 0
      margin-top: 0
      right: -1rem

  > li.logout-desktop
    display: none

@media (max-width: 991px) 
  .menu 
    
    > li 
      overflow: hidden
    
    > li.dropdown
      display: none

    > li.logout-desktop
      display: flex

  [type="checkbox"] ~ label.menu-button-container 
    display: flex

  .top-nav > ul.menu 
    position: absolute
    top: 0
    margin-top: 50px
    left: 0
    flex-direction: column
    width: 100%
    justify-content: center
    align-items: center

  #menu-toggle ~ .menu li 
    height: 0
    margin: 0
    padding: 0
    border: 0
    transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1)

  #menu-toggle:checked ~ .menu li 
    border: 1px solid #333
    height: 2.5em
    padding: 0.5em
    transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1)

  .menu > li 
    display: flex
    justify-content: center
    margin: 0
    padding: 0.5em 0
    width: 100%
    // color: white
    background-color: #222

  .menu > li:not(:last-child) 
    border-bottom: 1px solid #444
</style>
~
EOF
cat <<'EOF' | puravida layouts/default.vue ~
<template>
  <div>
    <NavDefault />
    <Nuxt />
  </div>
</template>
~
EOF
echo -e "\n\n🦄 Home\n\n"
cat <<'EOF' | puravida pages/index.vue ~
<template>
  <main class="container">
    <h1>Rails 7 Nuxt 2 Admin Boilerplate</h1>
    
    <h2 class="small-bottom-margin">Features</h2>
    <ul class="features">
      <li>Admin dashboard</li>
      <li>Placeholder users</li>
      <li>Placeholder user item ("car")</li>
    </ul>

    <h3 class="small-bottom-margin stack">Stack</h3>
    <div class="aligned-columns">
      <p><span>frontend:</span> Nuxt 2</p>
      <p><span>backend API:</span> Rails 7</p>
      <p><span>database:</span> Postgres</p>
      <p><span>styles:</span> Sass</p>
      <p><span>css framework:</span> Pico.css</p>
      <p><span>e2e tests:</span> Cypress</p>
      <p><span>api tests:</span> RSpec</p>
    </div>

    <h3 class="small-bottom-margin tools">Tools</h3>
    <div class="aligned-columns">
      <p><span>user avatars:</span> local active storage</p>
      <p><span>backend auth:</span> bcrypt & jwt</p>
      <p><span>frontend auth:</span> nuxt auth module</p>
    </div>

    <h3 class="small-bottom-margin">User Logins</h3>
    <table class="half-width">
      <tr><th>Email</th><th>Password</th><th>Notes</th></tr>
      <tr><td>michaelscott@dundermifflin.com</td><td>password</td><td>(admin)</td></tr>
      <tr><td>jimhalpert@dundermifflin.com</td><td>password</td><td></td></tr>
      <tr><td>pambeesly@dundermifflin.com</td><td>password</td><td></td></tr>
    </table>
    
    <p class="big-bottom-margin">
      <NuxtLink to="/log-in" role="button" class="secondary">Log In</NuxtLink> 
      <NuxtLink to="/sign-up" role="button" class="contrast outline">Sign Up</NuxtLink>
    </p>    

  </main>
</template>

<script>
export default { auth: false }
</script>
~
EOF
cat <<'EOF' | puravida components/Notification.vue ~
<template>
  <div class="notification is-danger">
    {{ message }}
  </div>
</template>

<script>
export default {
  name: 'Notification',
  props: ['message']
}
</script>
~
EOF

echo -e "\n\n🦄 Login & Signup Pages\n\n"
cat <<'EOF' | puravida pages/log-in.vue ~
<template>
  <main class="container">
    <h2>Log In</h2>
    <Notification :message="error" v-if="error"/>
    <form method="post" @submit.prevent="login">
      <div>
        <label>Email</label>
        <div>
          <input
            type="email"
            name="email"
            v-model="email"
          />
        </div>
      </div>
      <div>
        <label>Password</label>
        <div>
          <input
            type="password"
            name="password"
            v-model="password"
          />
        </div>
      </div>
      <div>
        <button type="submit">Log In</button>
      </div>
    </form>
    <div>
      <p>
        Don't have an account? <NuxtLink to="/sign-up">Sign up</NuxtLink>
      </p>
    </div>
  </main>
</template>

<script>
import Notification from '~/components/Notification'
export default {
  auth: false,
  components: {
    Notification,
  },
  data() {
    return {
      email: '',
      password: '',
      error: null
    }
  },
  methods: {
    async login() {
      this.$auth.loginWith('local', {
        data: {
          email: this.email,
          password: this.password
        }
      }).then (() => {
        const id = this.$auth.$state.user.id
        this.$router.push(`/users/${id}`)
      })
    }
  }
}
</script>
~
EOF
cat <<'EOF' | puravida pages/sign-up.vue ~
<template>
  <main class="container">
    <UserForm />      
  </main>
</template>

<script>
export default { auth: false }
</script>
~
EOF
cat <<'EOF' | puravida store/index.js ~
export const getters = {
  isAuthenticated(state) {
    return state.auth.loggedIn
  },

  isAdmin(state) {
    if (state.auth.user && state.auth.user.admin !== null && state.auth.user.admin == true) { 
        return true
    } else {
      return false
    } 
  },

  loggedInUser(state) {
    return state.auth.user
  }
}
~
EOF

echo -e "\n\n🦄 Admin Page\n\n"

cat <<'EOF' | puravida pages/admin/index.vue ~
<template>
  <main class="container">
    <h1>Admin</h1>
    <p>Number of users: {{ this.users.length }}</p>
    <p>Number of admins: {{ (this.users.filter((obj) => obj.admin === true)).length }}</p>
    <p>Number of cars: {{ this.cars.length }}</p>
    <p>Number of maintenances: {{ this.maintenances.length }}</p>
    <p>Number of documents: {{ this.documents.length }}</p>
    <p><NuxtLink to="/users">Users</NuxtLink></p>
    <p><NuxtLink to="/cars?admin=true">Cars</NuxtLink></p>
    <p><NuxtLink to="/maintenances?admin=true">Maintenances</NuxtLink></p>
    <p><NuxtLink to="/documents?admin=true">Documents</NuxtLink></p>
  </main>
</template>

<script>
export default { 
  middleware: 'adminOnly',
  layout: 'admin',
  data: () => ({ 
    users: [],
    cars: [],
    maintenances: [],
    documents: []
  }),
  async fetch() { 
    this.users = await this.$axios.$get('users')
    this.cars = await this.$axios.$get('cars')
    this.maintenances = await this.$axios.$get('maintenances')
    this.documents = await this.$axios.$get('documents')
  }
}
</script>
~
EOF


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