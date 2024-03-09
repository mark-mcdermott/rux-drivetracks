<template>
  <main class="container">
    <DocumentForm />
  </main>
</template>

<script>
export default { middleware: 'currentOrAdmin-showEdit' }
</script>
