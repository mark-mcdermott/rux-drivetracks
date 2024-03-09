<template>
  <section>
    <div v-for="maintenance in maintenances" :key="maintenance.id">
      <MaintenanceCard :maintenance="maintenance" :maintenances= "maintenances" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    maintenances: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.maintenances = await this.$axios.$get('maintenances')
    } else if (idQuery) {
      this.maintenances = await this.$axios.$get('maintenances', {
        params: { user_id: idQuery }
      })
    } else {
      this.maintenances = await this.$axios.$get('maintenances', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
