<template>
  <main class="container">
    <h1>Cars</h1>
    <NuxtLink to="/cars/new" role="button">Add Car</NuxtLink>
    <CarSet />
  </main>
</template>
<script>
export default { middleware: 'currentOrAdmin-index' }
</script>
