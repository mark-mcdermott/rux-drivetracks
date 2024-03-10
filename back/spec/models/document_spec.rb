# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Document, type: :model do
  fixtures :users, :cars, :maintenances, :documents
  let(:valid_attributes) do
    {
      date: Date.parse('20200713'),
      name: 'name',
      notes: 'notes',
      documentable_type: 'Maintenance',
      documentable_id: maintenances(:fiat_alignment).id
    }
  end
  let(:invalid_attributes) do
    {
      date: Date.parse('20200713'),
      name: 'name',
      notes: 'notes',
      documentable_type: 'Maintenance',
      documentable_id: -1
    }
  end

  it 'is valid with valid attributes' do
    expect(described_class.new(valid_attributes)).to be_valid
  end

  it 'is not valid width poorly formed email' do
    expect(described_class.new(invalid_attributes)).not_to be_valid
  end
end
