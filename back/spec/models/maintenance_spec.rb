# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Maintenance, type: :model do
  fixtures :users, :cars, :maintenances
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

  it 'is valid with valid attributes' do
    expect(described_class.new(valid_attributes)).to be_valid
  end

  it 'is not valid width poorly formed email' do
    expect(described_class.new(invalid_attributes)).not_to be_valid
  end
end
