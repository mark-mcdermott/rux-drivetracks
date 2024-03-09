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
