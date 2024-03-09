<template>
  <main class="container">
    <MaintenanceForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
