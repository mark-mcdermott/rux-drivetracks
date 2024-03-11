export default function ({ route, store, redirect }) {
  const { isAdmin, loggedInUser, isAuthenticated } = store.getters
  const query = route.query
  const isQueryEmpty = Object.keys(query).length === 0 ? true : false
  const requested_user_id = parseInt(query['user_id'])
  const actual_user_id = loggedInUser.id
  const isUserRequestingOwnData = requested_user_id === actual_user_id
  const pathWithoutQuery = route.path.split('?')[0]
  const pathWithAdminQuery = `${pathWithoutQuery}?admin=true`

  if (!isAuthenticated) {
    return redirect('/')
  } else if (!isAdmin && !isQueryEmpty && !isUserRequestingOwnData) {
    const pathWithUserId = `${pathWithoutQuery}?user_id=${loggedInUser.id}`
    return redirect(pathWithUserId)
  } else if (isQueryEmpty) {
    return redirect(pathWithAdminQuery)
  }
}
