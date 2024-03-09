require 'rails_helper'
require 'database_cleaner/active_record'
RSpec.describe User, type: :model do
  let(:mock_1_valid_create_params) {{ name: "First1 Last1", email: "one@mail.com", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  let(:mock_1_invalid_create_params_email_poorly_formed) {{ name: "", email: "not_an_email", admin: "false", password: "password", avatar: fixture_file_upload("spec/fixtures/files/michael-scott.png", "image/png") }}
  it "is valid with valid attributes" do
    expect(User.new(mock_1_valid_create_params)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(User.new(mock_1_invalid_create_params_email_poorly_formed)).to_not be_valid
  end
end
