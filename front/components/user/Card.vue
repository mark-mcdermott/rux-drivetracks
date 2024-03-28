<template>
  <article>
    <h2>
      <NuxtLink :to="`/users/${user.data.attributes.id}?user_id=${loggedInUser.id}`">{{ user.name }}</NuxtLink>
      <NuxtLink :to="`/users/${user.data.attributes.id}/edit`"><font-awesome-icon icon="pencil" /></NuxtLink>
      <a @click.prevent=deleteUser(user.data.attributes.id) href="#"><font-awesome-icon icon="trash" /></a>
    </h2>
    <p>id: {{ user.data.attributes.id }}</p>
    <p>email: {{ user.data.attributes.email }}</p>
    <p v-if="user.data.attributes.avatar !== null" class="no-margin">avatar:</p>
    <img v-if="user.data.attributes.avatar !== null" :src="user.data.attributes.avatar" />
    <p v-if="isAdmin">admin: {{ user.data.attributes.admin }}</p>
  </article>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
  name: 'UserCard',
  computed: {
    ...mapGetters(['isAdmin', 'indexOrShowPage', 'loggedInUser'])
  },
  props: {
    user: {
      type: Object,
      default: () => ({}),
    },
    users: {
      type: Array,
      default: () => ([]),
    },
  },
  methods: {
    uploadAvatar: function() {
      this.avatar = this.$refs.inputFile.files[0];
    },
    deleteUser: function(id) {
      this.$axios.$delete(`users/${id}`)
      const index = this.users.findIndex((i) => { return i.id === id })
      this.users.splice(index, 1)
      this.indexOrShowPage === 'show' ? this.$router.push('/users') : null
    }
  }
}
</script>
