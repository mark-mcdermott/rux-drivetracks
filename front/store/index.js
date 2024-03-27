export const getters = {
  isAuthenticated(state) {
    return state.auth.loggedIn
  },

  isAdmin(state) {
    if (state.auth.user && state.auth.user.admin !== null && state.auth.user.admin == true) { 
        return true
    } else {
      return false
    } 
  },

  loggedInUser(state) {
    return state.auth.user
  },

  indexOrShowPage() {
    const splitUrl = $nuxt.$route.path.split('/')
    const urlEnd = splitUrl[splitUrl.length-1]
    const regex = /cars|maintenances|documents/
    return regex.test(urlEnd) ? 'index' : 'show'
  }
}
