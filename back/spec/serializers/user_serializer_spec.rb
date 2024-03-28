require 'rails_helper'

RSpec.describe UserSerializer, type: :serializer do
  it 'serializes a user with expected attributes' do
    user = create(:user)
    user.avatar.attach(io: URI.open(Rails.root.join('app/assets/images/office-avatars/michael-scott.png').to_s),
                   filename: 'michael-scott.png')

    hash = described_class.new(user).serializable_hash
    data = hash[:data]
    attributes = data[:attributes]

    expect(attributes[:name]).to eq(user.name)
    expect(attributes[:id]).to eq(user.id)
    expect(attributes[:email]).to eq(user.email)
    expect(attributes[:avatar]).to match(/(http[s]?:\/\/www\.example\.com).*\/(michael-scott)\./)
    expect(attributes[:admin]).to eq(user.admin)
  end
end
