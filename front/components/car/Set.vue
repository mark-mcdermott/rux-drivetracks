<template>
  <section>
    <div v-for="car in cars" :key="car.id">
      <CarCard :car="car" :cars="cars" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    cars: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.cars = await this.$axios.$get('cars')
    } else if (idQuery) {
      this.cars = await this.$axios.$get('cars', {
        params: { user_id: idQuery }
      })
    } else {
      this.cars = await this.$axios.$get('cars', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
