# frozen_string_literal: true

class CreateMaintenances < ActiveRecord::Migration[7.0]
  def change
    create_table :maintenances do |t|
      t.date :date
      t.string :description
      t.string :vendor
      t.decimal :cost, precision: 10, scale: 2
      t.references :car, null: false, foreign_key: { on_delete: :cascade }
      t.timestamps
    end
  end
end
