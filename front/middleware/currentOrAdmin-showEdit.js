import { mapGetters } from 'vuex'
export default function ({ route, store, redirect }) {
  const { isAdmin, loggedInUser } = store.getters
  const url = route.fullPath;
  const splitPath = url.split('/')
  let elemId = null
  let isElemUsers = false
  let isCar = false;
  let isMaintenance = false;
  let isDocument = false;
  let isUser = false;
  const userCars = loggedInUser.car_ids
  const userMaintenances = loggedInUser.maintenances_ids
  const userDocuments = loggedInUser.documents_ids

  if (url.includes("document")) {
    isDocument = true
  } else if (url.includes("maintenance")) { 
    isMaintenance = true
  } else if (url.includes("car")) {
    isCar = true
  } else if (url.includes("users")) {
    isUser = true
  }

  if (isEditPage(url)) {
    elemId = parseInt(splitPath[splitPath.length-2])
  } else if (isShowPage(url)) {
    elemId = parseInt(splitPath[splitPath.length-1])
  }
  
  if (isCar) {
    isElemUsers = userCars.includes(elemId) ? true : false
  } else if (isMaintenance) {
    isElemUsers = userMaintenances.includes(elemId) ? true : false
  } else if (isDocument) {
    isElemUsers = userDocuments.includes(elemId) ? true : false
  } else if (isUser) {
    isElemUsers = loggedInUser.id === elemId ? true : false
  }

  if (!isAdmin && !isElemUsers) {
    return redirect('/')
  }
}

function isEditPage(url) {
  return url.includes("edit") ? true : false
}

function isShowPage(url) {
  const urlWithoutQuery = url.split('?')[0]
  const splitUrl = urlWithoutQuery.split('/')
  return (!isNaN(splitUrl[splitUrl.length-1]) && !isEditPage(url)) ? true : false
}
