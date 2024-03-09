require 'rails_helper'

RSpec.describe Document, type: :model do
  fixtures :users, :cars, :maintenances, :documents
  let(:valid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: maintenances(:fiat_alignment).id
  }}
  let(:invalid_attributes) {{ 
    date: Date.parse("20200713"),
    name: "name",
    notes: "notes",
    documentable_type: "Maintenance",
    documentable_id: -1
  }}

  it "is valid with valid attributes" do
    expect(Document.new(valid_attributes)).to be_valid
  end
  it "is not valid width poorly formed email" do
    expect(Document.new(invalid_attributes)).to_not be_valid
  end
end
