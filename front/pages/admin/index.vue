<template>
  <main class="container">
    <h1>Admin</h1>
    <p>Number of users: {{ this.users.length }}</p>
    <p>Number of admins: {{ (this.users.filter((obj) => obj.admin === true)).length }}</p>
    <p>Number of cars: {{ this.cars.length }}</p>
    <p>Number of maintenances: {{ this.maintenances.length }}</p>
    <p>Number of documents: {{ this.documents.length }}</p>
    <p><NuxtLink to="/users">Users</NuxtLink></p>
    <p><NuxtLink to="/cars?admin=true">Cars</NuxtLink></p>
    <p><NuxtLink to="/maintenances?admin=true">Maintenances</NuxtLink></p>
    <p><NuxtLink to="/documents?admin=true">Documents</NuxtLink></p>
  </main>
</template>

<script>
export default { 
  middleware: 'adminOnly',
  layout: 'admin',
  data: () => ({ 
    users: [],
    cars: [],
    maintenances: [],
    documents: []
  }),
  async fetch() { 
    this.users = await this.$axios.$get('users')
    this.cars = await this.$axios.$get('cars')
    this.maintenances = await this.$axios.$get('maintenances')
    this.documents = await this.$axios.$get('documents')
  }
}
</script>
