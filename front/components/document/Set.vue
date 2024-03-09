<template>
  <section>
    <div v-for="document in documents" :key="document.id">
      <DocumentCard :document="document" :documents= "documents" />
    </div>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  computed: { ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser']) }, 
  data: () => ({
    documents: []
  }),
  async fetch() {
    const query = this.$store.$auth.ctx.query
    const adminQuery = query.admin
    const idQuery = query.user_id
    
    if (this.isAdmin && adminQuery) {
      this.documents = await this.$axios.$get('documents')
    } else if (idQuery) {
      this.documents = await this.$axios.$get('documents', {
        params: { user_id: idQuery }
      })
    } else {
      this.documents = await this.$axios.$get('documents', {
        params: { user_id: this.loggedInUser.id }
      })
    }
  }
}
</script>
