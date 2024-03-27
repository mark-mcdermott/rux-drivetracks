require 'rails_helper'

RSpec.describe CarSerializer, type: :serializer do
  it 'serializes a car with expected attributes' do
    user = User.find_by(email: 'michaelscott@dundermifflin.com')
    car = create(
      :car,
      user:,
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
      initial_mileage: 47_361
    )
    car.image.attach(fixture_file_upload(Rails.root.join('spec/fixtures/files/fiat-500.jpg'), 'image/jpeg'))

    hash = described_class.new(car).serializable_hash
    data = hash[:data]
    attributes = data[:attributes]

    expect(attributes[:name]).to eq "Jim's Fiat 500"
    expect(attributes[:userName]).to eq user.name
    expect(attributes[:image]).to be_kind_of(String)
    expect(attributes[:image]).to match(/http.*fiat-500\.jpg/)
    expect(attributes[:make]).to eq 'Fiat'
    expect(attributes[:model]).to eq '500'
    expect(attributes[:trim]).to eq 'Sport'
    expect(attributes[:color]).to eq 'Yellow'
    expect(attributes[:body]).to eq 'Hatchback'
    expect(attributes[:plate]).to eq '6XYK922'
    expect(attributes[:vin]).to eq '3C3CFFBR0CT382584'
    expect(attributes[:year]).to eq 2012
    expect(attributes[:cost]).to eq 10_235.0
    expect(attributes[:purchaseVendor]).to eq 'Ted Fleid'
    expect(attributes[:initialMileage]).to eq 47_361
    expect(attributes[:userId]).to eq user.id
  end
end
