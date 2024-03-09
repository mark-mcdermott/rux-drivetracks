<template>
  <main class="container">
    <CarForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
