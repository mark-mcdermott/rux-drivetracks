# frozen_string_literal: true

class CreateCars < ActiveRecord::Migration[7.0]
  def change
    create_table :cars do |t|
      t.string :name, null: false
      t.integer :year
      t.string :make
      t.string :model
      t.string :trim
      t.string :body
      t.string :color
      t.string :plate
      t.string :vin
      t.decimal :cost, precision: 10, scale: 2
      t.integer :initial_mileage
      t.date :purchase_date
      t.string :purchase_vendor
      t.references :user, null: false, foreign_key: { on_delete: :cascade }
      t.timestamps
    end
  end
end
