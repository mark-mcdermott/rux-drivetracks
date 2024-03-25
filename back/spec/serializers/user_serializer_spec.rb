require 'rails_helper'

RSpec.describe UserSerializer, type: :serializer do
  it 'serializes a user with expected attributes' do
    user = create(:user, name: 'John Doe')

    hash = described_class.new(user).serializable_hash
    data = hash[:data]
    attributes = data[:attributes]

    expect(attributes[:name]).to eq 'John Doe'
  end
end
