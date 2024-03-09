<template>
  <main class="container">
    <h1>Maintenances</h1>
    <NuxtLink to="/maintenances/new" role="button">Add Maintenance</NuxtLink>
    <MaintenanceSet />
  </main>
</template>
<script>
export default { middleware: 'currentOrAdmin-index' }
</script>
