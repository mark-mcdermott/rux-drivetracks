FactoryBot.define do
  factory :document do
    documentable_type { "Car" }
    documentable_id { 1 }
  end
end
