<template>
  <main class="container">
    <section>
      <MaintenanceCard :maintenance="maintenance" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ maintenance: {} }),
  async fetch() { this.maintenance = await this.$axios.$get(`maintenances/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteMaintenance: function(id) {
      this.$axios.$delete(`maintenances/${this.$route.params.id}`)
      this.$router.push('/maintenances')
    }
  }
}
</script>
