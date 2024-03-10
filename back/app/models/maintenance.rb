# frozen_string_literal: true

class Maintenance < ApplicationRecord
  belongs_to :car
  # has_many_attached :images
  has_many :documents, as: :documentable
  validates :date, presence: true
  validates :description, presence: true
end
