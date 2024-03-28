class UserSerializer
  include JSONAPI::Serializer
  attributes :id, :email, :name, :admin

  attribute :avatar do |object|
    Rails.application.routes.url_helpers.url_for(object.avatar) if object.avatar.present?
  end
end
