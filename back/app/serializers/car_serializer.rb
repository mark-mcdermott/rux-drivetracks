class CarSerializer
  include JSONAPI::Serializer

  set_key_transform :camel_lower
  belongs_to :user
  attributes :name, :year, :make, :model, :trim, :body,
             :color, :plate, :vin, :initial_mileage, :purchase_vendor,
             :purchase_date, :user_id, :cost

  attribute :user_name do |object|
    object.user.name
  end

  attribute :cost do |object|
    object.cost.to_f
  end

  attribute :image do |object|
    Rails.application.routes.url_helpers.url_for(object.image) if object.image.attachment
  end
end
