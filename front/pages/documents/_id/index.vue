<template>
  <main class="container">
    <section>
      <DocumentCard :document="document" />
    </section>
  </main>
</template>

<script>
export default {
  middleware: 'currentOrAdmin-showEdit',
  data: () => ({ document: {} }),
  async fetch() { this.document = await this.$axios.$get(`documents/${this.$route.params.id}`) },
  methods: {
    uploadImage: function() { this.image = this.$refs.inputFile.files[0] },
    deleteDocument: function(id) {
      this.$axios.$delete(`documents/${this.$route.params.id}`)
      this.$router.push('/documents')
    }
  }
}
</script>
