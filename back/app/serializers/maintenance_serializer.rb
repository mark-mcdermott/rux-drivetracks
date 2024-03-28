class MaintenanceSerializer
  include JSONAPI::Serializer
  belongs_to :car
  has_many :documents
  attributes :date, :descripition, :vendor, :cost, :car_id, :documents
end
