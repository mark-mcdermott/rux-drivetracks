# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Car, type: :model do
  let(:car) { create(:car) }

  it 'is valid with valid attributes' do
    expect(car).to be_valid
  end

  it 'is not valid when name too short' do
    car.name = 'car'
    expect(car).not_to be_valid
  end

  it 'is not valid when name too long' do
    car.name = 'c' * 255
    expect(car).not_to be_valid
  end

  it 'is not valid without a user' do
    car.user = nil
    expect(car).not_to be_valid
  end
end
