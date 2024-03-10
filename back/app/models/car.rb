# frozen_string_literal: true

class Car < ApplicationRecord
  belongs_to :user
  has_many :maintenances, dependent: :destroy
  has_many :documents, as: :documentable
  has_one_attached :image
  validates :name, presence: true, allow_blank: false, length: { minimum: 4, maximum: 254 }
end
