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
