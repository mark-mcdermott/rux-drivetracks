<template>
  <article>
    <h2>
      <NuxtLink :to="`/cars/${car.id}?user_id=${loggedInUser.id}`">{{ car.name }}</NuxtLink> 
      <NuxtLink :to="`/cars/${car.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteCar(car.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ car.id }}</p>
    <p v-if="car.image !== null" class="no-margin">image:</p>
    <img v-if="car.image !== null" :src="car.image" />
    <p>year: {{ car.year }}</p>
    <p>make: {{ car.make }}</p>
    <p>model: {{ car.model }}</p>
    <p>trim: {{ car.trim }}</p>
    <p>body: {{ car.body }}</p>
    <p>color: {{ car.color }}</p>
    <p>plate: {{ car.plate }}</p>
    <p>vin: {{ car.vin }}</p>
    <p>cost: {{ car.cost }}</p>
    <p>initial_mileage: {{ car.initial_mileage }}</p>
    <p>purchase_date: {{ car.purchase_date }}</p>
    <p>purchase_vendor: {{ car.purchase_vendor }}</p>
    <h4 v-if="car.maintenances !== null">Maintenances</h4>
    <ul v-if="car.maintenances !== null">
      <li v-for="maintenance in car.maintenances" :key="maintenance.id">
        <NuxtLink :to="`/maintenances/${maintenance.id}`">{{ maintenance.description }}</NuxtLink>
      </li>
    </ul>
    <h4 v-if="car.documents !== null">Documents</h4>
    <ul v-if="car.documents !== null">
      <li v-for="document in car.documents" :key="document.id">
        <NuxtLink :to="`/documents/${document.id}`">{{ document.name }}</NuxtLink>
      </li>
    </ul>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'CarCard',
  computed: { 
    ...mapGetters(['isAdmin', 'indexOrShowPage', 'loggedInUser']),
  },
  props: {
    car: {
      type: Object,
      default: () => ({}),
    },
    cars: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteCar: function(id) {
      this.$axios.$delete(`cars/${id}`)
      const index = this.cars.findIndex((i) => { return i.id === id })
      this.cars.splice(index, 1)
      this.indexOrShowPage === 'show' ? this.$router.push(`/cars?user_id=${this.loggedInUser.id}`) : null
    }
  }
}
</script>
