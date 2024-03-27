<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Maintenance</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Maintenance</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Date: </p><date-picker v-model="date" valueType="format"></date-picker>
        <p>Description: </p><input v-model="description">
        <p>Vendor: </p><input v-model="vendor">
        <p>Cost: </p><CurrencyInput v-model="cost" />
        <!-- <p class="no-margin">Image: </p>
        <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />    
        <input type="file" ref="inputFile" @change=uploadImage()> -->
        <p>Car: {{ carId }}</p>
        <select v-if="editOrNew === 'new'" name="car" @change="selectCar($event)">
          <option value=""></option>
          <option v-for="car in cars" :key="car.id" :value="car.id">{{ car.name }} - {{ car.description }}</option>
        </select>
        <button v-if="editOrNew !== 'edit'" @click.prevent=createMaintenance>Create Maintenance</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editMaintenance>Edit Maintenance</button>
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
      date: null,
      description: "",
      vendor: "",
      cost: "",
      // image: "",
      editOrNew: "",
      hideImage: false,
      cars: [],
      carId: ""
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const maintenance = await this.$axios.$get(`maintenances/${this.$route.params.id}`)
      this.date = maintenance.date
      this.description = maintenance.description,
      this.vendor = maintenance.vendor
      this.cost = maintenance.cost
      this.image = maintenance.image
      this.carId = maintenance.carId 
    }
    if (this.editOrNew == 'new') {
      this.cars = await this.$axios.$get('/cars', {
        params: { user_id: this.$auth.$state.user.id }
      })
    }
  },
  methods: {
    // uploadImage: function() {
    //   this.image = this.$refs.inputFile.files[0]
    //   this.hideImage = true
    // },
    createMaintenance: function() {
      const params = {
        'date': this.date,
        'description': this.description,
        'vendor': this.vendor,
        'cost': this.cost,
        'image': this.image,
        'car_id': this.carId
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('maintenances', payload)
        .then((res) => {
          const maintenanceId = res.id
          this.$router.push(`/maintenances/${maintenanceId}`)
        })
    },
    editMaintenance: function() {
      // let params = {}
      let params = { 'name': this.name, 'date': this.date, 'description': this.description, 'vendor': this.vendor, 'cost': this.cost }
      // const filePickerFile = this.$refs.inputFile.files[0]
      // if (!filePickerFile) {
      //   params = { 'name': this.name, 'date': this.date, 'description': this.description, 'vendor': this.vendor, 'cost': this.cost }
      // } else {
      //   params = { 'name': this.name, 'date': this.date, 'description': this.description, 'vendor': this.vendor, 'cost': this.cost, 'image': this.image }
      // } 
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/maintenances/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/maintenances/${this.$route.params.id}`)
        })
    },
    selectCar: function(event) {
      this.carId = event.target.value
    }
  }
}
</script>
