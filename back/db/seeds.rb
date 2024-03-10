# frozen_string_literal: true

user = User.create(name: 'Michael Scott', email: 'michaelscott@dundermifflin.com', admin: 'true', password: 'password')
user.avatar.attach(io: URI.open(Rails.root.join('app/assets/images/office-avatars/michael-scott.png').to_s),
                   filename: 'michael-scott.png')
user.save!
user = User.create(name: 'Jim Halpert', email: 'jimhalpert@dundermifflin.com', admin: 'false', password: 'password')
user.avatar.attach(io: URI.open(Rails.root.join('app/assets/images/office-avatars/jim-halpert.png').to_s),
                   filename: 'jim-halpert.png')
user.save!
user = User.create(name: 'Pam Beesly', email: 'pambeesly@dundermifflin.com', admin: 'false', password: 'password')
user.avatar.attach(io: URI.open(Rails.root.join('app/assets/images/office-avatars/pam-beesly.png').to_s),
                   filename: 'jim-halpert.png')
user.save!
car = Car.create(name: "Michael's Fiat 500", make: 'Fiat', model: '500', trim: 'Sport', color: 'Yellow',
                 body: 'Hatchback', plate: '6XYK922', vin: '3C3CFFBR0CT382584', year: 2012, cost: '10235.00', purchase_vendor: 'Ted Fleid', initial_mileage: 47_361, purchase_date: Date.parse('20180606'), user_id: 1)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/fiat-500.jpg').to_s), filename: 'fiat-500.jpg')
car.save!
car = Car.create(name: "Michael's Honda Civic", make: 'Honda', model: 'Civic', trim: 'Vp', color: 'Blue',
                 body: 'Sedan', plate: '4HGJ708', vin: '2HGEJ6618XH589506', year: 1999, cost: '10352', purchase_vendor: 'Howdy Honda', initial_mileage: 78_032, purchase_date: Date.parse('20160713'), user_id: 1)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/honda-civic.jpg').to_s),
                 filename: 'honda-civic.jpg')
car.save!
car = Car.create(name: "Jim's Hyundai Elantra", make: 'Hyundai', model: 'Elantra', trim: 'GLS', color: 'Black',
                 body: 'Sedan', plate: '8CEU662', vin: 'KMHDU46D17U090264', year: 2007, cost: '15000.00', purchase_vendor: 'Feit Hyundai', initial_mileage: 53_032, purchase_date: Date.parse('20200115'), user_id: 2)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/hyundai-elantra.jpg').to_s),
                 filename: 'hyundai-elantra.jpg')
car.save!
car = Car.create(name: "Jim's Nissan Leaf", make: 'Nissan', model: 'Leaf', trim: 'SV', color: 'Silver',
                 body: 'Hatchback', plate: 'ABC123', vin: '1N4AZ1CP8LC310110', year: 2020, cost: '22590.00', purchase_vendor: 'Carvana', initial_mileage: 21_440, purchase_date: Date.parse('20230429'), user_id: 2)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/nissan-leaf.jpg').to_s),
                 filename: 'nissan-leaf.jpg')
car.save!
car = Car.create(name: "Pam's Scion Xb", make: 'Scion', model: 'Xb', trim: 'Base / Parklan Edition', color: 'Gray',
                 body: 'Wagon', plate: '7MBE060', vin: 'JTLZE4FE0FJ074884', year: 2015, cost: '25867.00', purchase_vendor: 'Craigslist', initial_mileage: 35_631, purchase_date: Date.parse('20201109'), user_id: 3)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/scion.jpg').to_s), filename: 'scion.jpg')
car.save!
car = Car.create(name: "Pam's Toyota Camry", make: 'Toyota', model: 'Camry', trim: 'LE', color: 'Black', body: 'Sedan',
                 plate: 'HDH1439', vin: '4T1BE46K49U358097', year: 2009, cost: '7300', purchase_vendor: 'Tanne Toyota', initial_mileage: 134_087, purchase_date: Date.parse('20100513'), user_id: 3)
car.image.attach(io: URI.open(Rails.root.join('app/assets/images/cars/toyota-camry.jpg').to_s),
                 filename: 'toyota-camry.jpg')
car.save!
maintenance = Maintenance.create(date: Date.parse('20200713'), description: 'Alignment', vendor: 'Pep Boys',
                                 cost: '350.00', car_id: 1)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-alignment-1.jpg"), filename: "fiat-alignment-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-alignment-2.jpg"), filename: "fiat-alignment-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20210812'), description: 'Oil Change', vendor: 'Jiffy Lube',
                                 cost: '78.00', car_id: 1)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-oil-change-1.jpg"), filename: "fiat-oil-change-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/fiat-oil-change-2.jpg"), filename: "fiat-oil-change-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20170123'), description: 'Brake Repair', vendor: 'WalMart',
                                 cost: '400.00', car_id: 2)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-brake-repair-1.jpg"), filename: "civic-brake-repair-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-brake-repair-2.jpg"), filename: "civic-brake-repair-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20200311'), description: 'Tire Rotation', vendor: 'Goodyear',
                                 cost: '105.00', car_id: 2)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-tire-rotation-1.jpg"), filename: "civic-tire-rotation-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/civic-tire-rotation-2.jpg"), filename: "civic-tire-rotation-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20200111'), description: 'New Tires', vendor: "Scott's",
                                 cost: '812.00', car_id: 3)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-new-tires-1.jpg"), filename: "elantra-new-tires-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-new-tires-2.jpg"), filename: "elantra-new-tires-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20230627'), description: 'Repaired Body Dents',
                                 vendor: 'Tenede Auto', cost: '1343.00', car_id: 3)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-repaired-body-1.jpg"), filename: "elantra-repaired-body-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/elantra-repaired-body-2.jpg"), filename: "elantra-repaired-body-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20150614'), description: 'Windshield Replacement',
                                 vendor: '45th St. Car Repair', cost: '800.00', car_id: 4)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-windshield-replacement-1.jpg"), filename: "leaf-windshield-replacement-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-windshield-replacement-2.jpg"), filename: "leaf-windshield-replacement-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20170811'), description: 'New Spark Plugs',
                                 vendor: "Jim & Tony's Automotive Service", cost: '5.00', car_id: 4)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-new-spark-plugs-1.jpg"), filename: "leaf-new-spark-plugs-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/leaf-new-spark-plugs-2.jpg"), filename: "leaf-new-spark-plugs-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20200909'), description: 'Engine Overhaul', vendor: 'Auto Stoppe',
                                 cost: '5932.00', car_id: 5)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-engine-overhaul-1.jpg"), filename: "scion-engine-overhaul-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-engine-overhaul-2.jpg"), filename: "scion-engine-overhaul-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20201030'), description: '50,000 Mile Maintenance',
                                 vendor: 'Dealership', cost: '0', car_id: 5)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-5k-mile-maintenance-1.jpg"), filename: "scion-5k-mile-maintenance-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/scion-5k-mile-maintenance-2.jpg"), filename: "scion-5k-mile-maintenance-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20220903'), description: 'Fuel Line Replacement',
                                 vendor: 'Foreign Auto Austin', cost: '37.00', car_id: 6)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-fuel-line-1.jpg"), filename: "camry-fuel-line-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-fuel-line-2.jpg"), filename: "camry-fuel-line-2.jpg")
maintenance.save!
maintenance = Maintenance.create(date: Date.parse('20230601'), description: 'Replaced Radiator',
                                 vendor: "Blan's Auto Repair", cost: '400.00', car_id: 6)
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-replaced-radiator-1.jpg"), filename: "camry-replaced-radiator-1.jpg")
# maintenance.images.attach(io: URI.open("#{Rails.root}/app/assets/images/maintenances/camry-replaced-radiator-2.jpg"), filename: "camry-replaced-radiator-2.jpg")
maintenance.save!
document = Document.create(name: 'title-fiat-500', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 1)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-fiat-500.gif').to_s), filename: 'title-fiat-500.gif'
)
document = Document.create(name: 'contract-fiat-500', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 1)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-fiat-500.webp').to_s), filename: 'contract-fiat-500.webp'
)
document = Document.create(name: 'title-honda-civic', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 2)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-honda-civic.png').to_s), filename: 'title-honda-civic.png'
)
document = Document.create(name: 'contract-honda-civic', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 2)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-honda-civic.png').to_s), filename: 'contract-honda-civic.png'
)
document = Document.create(name: 'title-hyundai-elantra', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 3)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-hyundai-elantra.pdf').to_s), filename: 'title-hyundai-elantra.pdf'
)
document = Document.create(name: 'contract-hyundai-elantra', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 3)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-hyundai-elantra.jpg').to_s), filename: 'contract-hyundai-elantra.jpg'
)
document = Document.create(name: 'title-nissan-leaf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 4)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-nissan-leaf.png').to_s), filename: 'title-nissan-leaf.png'
)
document = Document.create(name: 'contract-nissan-leaf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 4)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-nissan-leaf.png').to_s), filename: 'contract-nissan-leaf.png'
)
document = Document.create(name: 'title-scion', date: Date.parse('20200909'), notes: 'notes', documentable_type: 'Car',
                           documentable_id: 5)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-scion.jpg').to_s), filename: 'title-scion.jpg'
)
document = Document.create(name: 'contract-scion', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 5)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-scion.pdf').to_s), filename: 'contract-scion.pdf'
)
document = Document.create(name: 'title-toyota-camry', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 6)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/titles/title-toyota-camry.jpg').to_s), filename: 'title-toyota-camry.jpg'
)
document = Document.create(name: 'contract-toyota-camry', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Car', documentable_id: 6)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/car-documents/contracts/contract-toyota-camry.jpg').to_s), filename: 'contract-toyota-camry.jpg'
)
document = Document.create(name: 'fiat-alignment-1.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 1)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/fiat-alignment-1.png').to_s), filename: 'fiat-alignment-1.png'
)
document = Document.create(name: 'fiat-alignment-2.txt', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 1)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/fiat-alignment-2.txt').to_s), filename: 'fiat-alignment-2.txt'
)
document = Document.create(name: 'fiat-oil-change-1.txt', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 2)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/fiat-oil-change-1.txt').to_s), filename: 'fiat-oil-change-1.txt'
)
document = Document.create(name: 'fiat-oil-change-2.txt', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 2)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/fiat-oil-change-1.txt').to_s), filename: 'fiat-oil-change-1.txt'
)
document = Document.create(name: 'civic-brake-repair-1.jpg', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 3)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/civic-brake-repair-1.jpg').to_s), filename: 'civic-brake-repair-1.jpg'
)
document = Document.create(name: 'civic-brake-repair-2.pdf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 3)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/civic-brake-repair-2.pdf').to_s), filename: 'civic-brake-repair-2.pdf'
)
document = Document.create(name: 'civic-tire-rotation-1.pdf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 4)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/civic-tire-rotation-1.pdf').to_s), filename: 'civic-tire-rotation-1.pdf'
)
document = Document.create(name: 'civic-tire-rotation-2.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 4)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/civic-tire-rotation-2.png').to_s), filename: 'civic-tire-rotation-2.png'
)
document = Document.create(name: 'elantra-new-tires-1.pdf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 5)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/elantra-new-tires-1.pdf').to_s), filename: 'elantra-new-tires-1.pdf'
)
document = Document.create(name: 'elantra-new-tires-2.pdf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 5)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/elantra-new-tires-2.pdf').to_s), filename: 'elantra-new-tires-2.pdf'
)
document = Document.create(name: 'elantra-repaired-body-1.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 6)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/elantra-repaired-body-1.png').to_s), filename: 'elantra-repaired-body-1.png'
)
document = Document.create(name: 'elantra-repaired-body-2.pdf', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 6)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/elantra-repaired-body-2.pdf').to_s), filename: 'elantra-repaired-body-2.pdf'
)
document = Document.create(name: 'leaf-windshield-replacement-1.webp', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 7)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/leaf-windshield-replacement-1.webp').to_s), filename: 'leaf-windshield-replacement-1.webp'
)
document = Document.create(name: 'leaf-windshield-replacement-2.webp', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 7)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/leaf-windshield-replacement-2.webp').to_s), filename: 'leaf-windshield-replacement-2.webp'
)
document = Document.create(name: 'leaf-new-spark-plugs-1.txt', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 8)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/leaf-new-spark-plugs-1.txt').to_s), filename: 'leaf-new-spark-plugs-1.txt'
)
document = Document.create(name: 'leaf-new-spark-plugs-2.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 8)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/leaf-new-spark-plugs-2.png').to_s), filename: 'leaf-new-spark-plugs-2.png'
)
document = Document.create(name: 'scion-engine-overhaul-1.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 9)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/scion-engine-overhaul-1.png').to_s), filename: 'scion-engine-overhaul-1.png'
)
document = Document.create(name: 'scion-engine-overhaul-2.jpg', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 9)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/scion-engine-overhaul-2.jpg').to_s), filename: 'scion-engine-overhaul-2.jpg'
)
document = Document.create(name: 'scion-5k-mile-maintenance-1.jpg', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 10)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/scion-5k-mile-maintenance-1.jpg').to_s), filename: 'scion-5k-mile-maintenance-1.jpg'
)
document = Document.create(name: 'scion-5k-mile-maintenance-2.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 10)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/scion-5k-mile-maintenance-2.png').to_s), filename: 'scion-5k-mile-maintenance-2.png'
)
document = Document.create(name: 'camry-fuel-line-1.txt', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 11)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/camry-fuel-line-1.txt').to_s), filename: 'camry-fuel-line-1.txt'
)
document = Document.create(name: 'camry-fuel-line-2.webp', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 11)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/camry-fuel-line-2.webp').to_s), filename: 'camry-fuel-line-2.webp'
)
document = Document.create(name: 'camry-replaced-radiator-1.png', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 12)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/camry-replaced-radiator-1.png').to_s), filename: 'camry-replaced-radiator-1.png'
)
document = Document.create(name: 'camry-replaced-radiator-2.webp', date: Date.parse('20200909'), notes: 'notes',
                           documentable_type: 'Maintenance', documentable_id: 12)
document.attachment.attach(
  io: URI.open(Rails.root.join('app/assets/images/documents/maintenance-documents/camry-replaced-radiator-2.webp').to_s), filename: 'camry-replaced-radiator-2.webp'
)
