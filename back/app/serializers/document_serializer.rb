class DocumentSerializer
  include JSONAPI::Serializer
  attributes :date, :name, :notes, :documentable_type, :documentable_id
end
