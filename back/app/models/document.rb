# frozen_string_literal: true

class Document < ApplicationRecord
  belongs_to :documentable, polymorphic: true
  has_one_attached :attachment
end
