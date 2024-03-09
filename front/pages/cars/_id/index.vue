<template>
  <main class="container">
    <section>
      <CarCard :car="car" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ car: {} }),
  async fetch() { this.car = await this.$axios.$get(`cars/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteCar: function(id) {
      this.$axios.$delete(`cars/${this.$route.params.id}`)
      this.$router.push('/cars')
    }
  }
}
</script>
