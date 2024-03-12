# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Car, type: :model do
  let(:car) { build_stubbed(:car) }

  describe 'relationships' do
    it { is_expected.to belong_to(:user) }
  end

  describe 'validations' do
    it 'is valid with valid attributes' do
      expect(car).to be_valid
    end

    it do
      expect(subject).to validate_length_of(:name)
        .is_at_least(4).is_at_most(254)
    end
  end
end
