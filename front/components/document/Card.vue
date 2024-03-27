<template>
  <article>
    <h2>
      <NuxtLink :to="`/documents/${document.id}?user_id=${loggedInUser.id}`">{{ document.name }}</NuxtLink> 
      <NuxtLink :to="`/documents/${document.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteDocument(document.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ document.id }}</p>
    <p>date: {{ document.date }}</p>
    <p>notes: {{ document.notes }}</p>
    <p>attachment: <a :href="document.attachment">{{ document.attachmentFile }}</a></p>
    <p v-if="document.hasOwnProperty('maintenanceDescription')">maintenance: <NuxtLink :to="`/maintenances/${document.maintenanceId}`">{{ document.maintenanceDescription }}</NuxtLink></p>
    <p>car: <NuxtLink :to="`/cars/${document.carId}`">{{ document.carName }}</NuxtLink></p>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'DocumentCard',
  computed: { 
    ...mapGetters(['isAdmin', 'indexOrShowPage', 'loggedInUser'])
  },
  props: {
    document: {
      type: Object,
      default: () => ({}),
    },
    documents: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadImage: function() {
      this.image = this.$refs.inputFile.files[0];
    },
    deleteDocument: function(id) {
      this.$axios.$delete(`documents/${id}`)
      const index = this.documents.findIndex((i) => { return i.id === id })
      this.documents.splice(index, 1)
      this.indexOrShowPage === 'show' ? this.$router.push('/documents') : null
    }
    
  }
}
</script>
