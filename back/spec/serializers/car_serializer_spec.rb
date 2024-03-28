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
    maintenance = Maintenance.create(date: Date.parse('20200713'), description: 'Alignment', vendor: 'Pep Boys',
                                 cost: '350.00', car_id: car.id)
    car_document = Document.create(name: 'title-fiat-500', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: car.id)
    maintenance_document = Document.create(name: 'fiat-alignment-1.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: maintenance.id)

    hash = described_class.new(car).serializable_hash
    data = hash[:data]
    relationships = hash[:data][:relationships]
    attributes = data[:attributes]

    expect(attributes[:name]).to eq "Jim's Fiat 500"
    expect(attributes[:userName]).to eq user.name
    expect(relationships[:maintenances][:data]).to include({id: maintenance.id.to_s, type: :maintenance})
    expect(relationships[:documents][:data]).to include({id: car_document.id.to_s, type: :document})
  end
end
