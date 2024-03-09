export default function ({ route, store, redirect }) {
  const { isAdmin, loggedInUser } = store.getters
  const query = route.query
  const isAdminRequest = query['admin'] ? true : false
  const isUserIdRequest = query['user_id'] ? true : false
  const isQueryEmpty = Object.keys(query).length === 0 ? true : false
  const userIdRequestButNotAdmin = isUserIdRequest && !isAdmin
  const requested_user_id = parseInt(query['user_id'])
  const actual_user_id = loggedInUser.id
  const allowedAccess = requested_user_id === actual_user_id ? true : false

  if ((isAdminRequest || isQueryEmpty) && !isAdmin) {
    return redirect('/')
  } else if (userIdRequestButNotAdmin && !allowedAccess) {
    return redirect('/cars?user_id=' + loggedInUser.id)
  }
}
