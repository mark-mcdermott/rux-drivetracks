<template>
  <main class="container">
    <h1>Documents</h1>
    <NuxtLink :to="`${newDocUrl}`" role="button">Add Document</NuxtLink>
    <DocumentSet />
  </main>
</template>
<script>
  export default { 
    middleware: 'currentOrAdmin-index',
    data () {
      return {
        newDocUrl: ""
      }
    },
    mounted() {
      this.newDocUrl = this.getNewDocUrl()
    },
    methods: {
      getNewDocUrl: () => {
        const url = "/documents/new"
        let query = ""
        if ($nuxt.$route.query && $nuxt.$route.query.user_id) {
          query = `?user_id=${$nuxt.$route.query.user_id}`
        }
        return url + query
      }
    }
  }
</script>
