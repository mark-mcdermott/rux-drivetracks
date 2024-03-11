<template>
  <article>
    <h2>
      <NuxtLink :to="`/maintenances/${maintenance.id}?user_id=${loggedInUser.id}`">{{ maintenance.description }}</NuxtLink> 
      <NuxtLink :to="`/maintenances/${maintenance.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteMaintenance(maintenance.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ maintenance.id }}</p>
    <p>date: {{ maintenance.date }}</p>
    <p>description: {{ maintenance.description }}</p>
    <p>vendor: {{ maintenance.vendor }}</p>
    <p>cost: {{ maintenance.cost }}</p>
        <p>car: <NuxtLink :to="`/cars/${maintenance.carId}`">{{ maintenance.carName }}</NuxtLink></p>
    <h4 v-if="maintenance.documents !== null">Documents</h4>
    <ul v-if="maintenance.documents !== null">
      <li v-for="document in maintenance.documents" :key="document.id">
        <NuxtLink :to="`/documents/${document.id}`">{{ document.name }}</NuxtLink>
      </li>
    </ul>
    <!-- <p v-if="maintenance.images !== null" class="no-margin">images:</p>
    <div v-if="maintenance.images !== null" :src="maintenance.image">
      <div v-for="image in maintenance.images" :key="image">
        <img :src="image" />
      </div>
    </div> -->
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'MaintenanceCard',
  computed: { 
    ...mapGetters(['isAdmin', 'indexOrShowPage', 'loggedInUser'])
  },
  props: {
    maintenance: {
      type: Object,
      default: () => ({}),
    },
    maintenances: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteMaintenance: function(id) {
      this.$axios.$delete(`maintenances/${id}`)
      const index = this.maintenances.findIndex((i) => { return i.id === id })
      this.maintenances.splice(index, 1)
      this.indexOrShowPage === 'show' ? this.$router.push('/maintenances') : null
    }
  }
}
</script>
