<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Car</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Car</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Name: </p><input v-model="name">
        <p class="no-margin">Image: </p>
        <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
        <input type="file" ref="inputFile" @change=uploadImage()>
        <p>year: </p><input v-model="year">
        <p>make: </p><input v-model="make">
        <p>model: </p><input v-model="model">
        <p>trim: </p><input v-model="trim">
        <p>body: </p><input v-model="body">
        <p>color: </p><input v-model="color">
        <p>plate: </p><input v-model="plate">
        <p>vin: </p><input v-model="vin">
        <p>cost: </p><CurrencyInput v-model="cost" />
        <p>initial_mileage: </p><input v-model="initial_mileage">
        <p>purchase_date: </p><date-picker v-model="purchase_date" valueType="format"></date-picker>
        <p>purchase_vendor: </p><input v-model="purchase_vendor">
        <button v-if="editOrNew !== 'edit'" @click.prevent=createCar>Create Car</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editCar>Edit Car</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
import DatePicker from 'vue2-datepicker';
import 'vue2-datepicker/index.css';
export default {
  components: { DatePicker },
  data () {
    return {
      name: "",
      description: "",
      image: "",
      year: null,
      make: "",
      model: "",
      trim: "",
      body: "",
      color: "",
      plate: "",
      vin: "",
      cost: "",
      initial_mileage: "",
      purchase_date: "",
      purchase_vendor: "",
      editOrNew: "",
      hideImage: false
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const car = await this.$axios.$get(`cars/${this.$route.params.id}`)
      this.name = car.name
      this.image = car.image
      this.year = car.year
      this.make = car.make
      this.model = car.model
      this.trim = car.trim
      this.body = car.body
      this.color = car.color
      this.plate = car.plate
      this.vin = car.vin
      this.cost = car.cost
      this.initial_mileage = car.initial_mileage
      this.purchase_date = car.purchase_date
      this.purchase_vendor = car.purchase_vendor
    }
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0]
      this.hideImage = true
    },
    getUserId() {
      const userIdQuery = $nuxt.$route.query.user_id
      this.userId = userIdQuery ? userIdQuery : null
    },
    createCar: function() {
      const userId = this.$auth.$state.user.id
      const params = {
        'name': this.name,
        'image': this.image,
        'year': this.year,
        'make': this.make,
        'model': this.model,
        'trim': this.trim,
        'body': this.body,
        'color': this.color,
        'plate': this.plate,
        'vin': this.vin,
        'cost': this.cost,
        'initial_mileage': this.initial_mileage,
        'purchase_date': this.purchase_date,
        'purchase_vendor': this.purchase_vendor,
        'user_id': userId
      }
      let payload = new FormData()
      
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('cars', payload)
        .then((res) => {
          const carId = res.id
          this.$router.push(`/cars/${carId}`)
        })
    },
    editCar: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        const userId = this.$auth.$state.user.id
        console.log('user id', userId)
        params = {
          'name': this.name,
          'year': this.year,
          'make': this.make,
          'model': this.model,
          'trim': this.trim,
          'body': this.body,
          'color': this.color,
          'plate': this.plate,
          'vin': this.vin,
          'cost': this.cost,
          'initial_mileage': this.initial_mileage,
          'purchase_date': this.purchase_date,
          'purchase_vendor': this.purchase_vendor,
          'user_id': userId
        }
        console.log('params', params)
      } else {
        params = { 
          'name': this.name,
          'image': this.image, 
          'year': this.year,
          'make': this.make,
          'model': this.model,
          'trim': this.trim,
          'body': this.body,
          'color': this.color,
          'plate': this.plate,
          'vin': this.vin,
          'cost': this.cost,
          'initial_mileage': this.initial_mileage,
          'purchase_date': this.purchase_date,
          'purchase_vendor': this.purchase_vendor,
          'user_id': userId
        }
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/cars/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/cars/${this.$route.params.id}`)
        })
    },
  }
}
</script>

