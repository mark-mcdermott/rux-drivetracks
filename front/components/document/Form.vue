<template>
  <section>
    <h1 v-if="editOrNew === 'edit'">Edit Document</h1>
    <h1 v-else-if="editOrNew === 'new'">Add Document</h1>
    <article>
      <form enctype="multipart/form-data">
        <p v-if="editOrNew === 'edit'">id: {{ $route.params.id }}</p>
        <p>Date: </p><date-picker v-model="date" valueType="format"></date-picker>
        <p>Name: </p><input v-model="name">
        <p>Notes: </p><textarea v-model="notes"></textarea>
        <p class="no-margin">Image: </p>
        <!-- <img v-if="!hideImage && editOrNew === 'edit'" :src="image" />     -->
        <input type="file" ref="inputFile" @change=uploadFile()>
        <p>Car or Maintenance Document: </p>
        <div>
          <input type="radio" id="car" value="Car" v-model="carOrMaintenance">
          <label for="car">Car</label>
        </div>
        <div>
          <input type="radio" id="maintenance" value="Maintenance" v-model="carOrMaintenance">
          <label for="maintenance">Maintenance</label>
        </div>
        <div v-if="editOrNew === 'new'">
          <select v-if="carOrMaintenance === 'Car'" name="Car" @change="selectCar($event)">
            <option value=""></option>
            <option v-for="car in cars" :key="car.id" :value="car.id">{{ car.name }}</option>
          </select>
          <select v-if="carOrMaintenance === 'Maintenance'" name="maintenance" @change="selectMaintenance($event)">
            <option value=""></option>
            <option v-for="maintenance in maintenances" :key="maintenance.id" :value="maintenance.id">{{ maintenance.description }} ({{ maintenance.carName }})</option>
          </select>
        </div>
        <button v-if="editOrNew !== 'edit'" @click.prevent=createDocument>Create Document</button>
        <button v-else-if="editOrNew == 'edit'" @click.prevent=editDocument>Edit Document</button>
      </form>
    </article>
  </section>
</template>

<script>
import { mapGetters } from 'vuex'
import DatePicker from 'vue2-datepicker';
import 'vue2-datepicker/index.css';
export default {
  components: { DatePicker },
  data () {
    return {
      date: null,
      name: "",
      notes: "",
      attachment: "",
      editOrNew: "",
      carOrMaintenance: "",
      userId: "",
      // hideImage: false,
      cars: [],
      carId: "",
      carIds: [],
      maintenances: [],
      maintenanceIds: "",
      maintenanceId: "",
      documents: [],
      documentIds: [],
      documentableId: ""
    }
  },
  mounted() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = splitPath[splitPath.length-1]
    this.getUserId()
    this.getCarsMaintsAndDocIds()
    
  },
  computed: {
    ...mapGetters(['isAuthenticated', 'isAdmin', 'loggedInUser`']),
  },
  async fetch() {
    const splitPath = $nuxt.$route.path.split('/')
    this.editOrNew = $nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]
    if ($nuxt.$route.path.split('/')[$nuxt.$route.path.split('/').length-1]=='edit') {
      const document = await this.$axios.$get(`documents/${this.$route.params.id}`)
      this.date = document.date
      this.name = document.name
      this.notes = document.notes
      this.description = document.description,
      this.attachment = document.image  
    }
    if (this.editOrNew == 'new') {
      this.maintenanceIds = 
      this.cars = await this.$axios.$get('/cars', { params: { user_id: this.$auth.$state.user.id } })
      this.maintenances = await this.$axios.$get('/maintenances', { params: { user_id: this.$auth.$state.user.id } })
    }
  },
  methods: {
    uploadFile: function() {
      this.attachment = this.$refs.inputFile.files[0]
      // this.hideImage = true
    },
    getUserId() {
      const userIdQuery = $nuxt.$route.query.user_id
      this.userId = userIdQuery ? userIdQuery : null
    },
    getCarsMaintsAndDocIds() {
      const user = this.$auth.user
      this.cars = user.cars
      this.maintenances = user.maintenances
      this.documents = user.documents
    },
    createDocument: function() {
      const params = {
        'date': this.date,
        'name': this.name,
        'notes': this.notes,
        'documentable_type': this.carOrMaintenance,
        'documentable_id': parseInt(this.documentableId)
      }
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$post('documents', payload)
        .then((res) => {
          const documentId = res.id
          this.$router.push(`/documents/${documentId}`)
        })
    },
    editDocument: function() {
      let params = {}
      const filePickerFile = this.$refs.inputFile.files[0]
      if (!filePickerFile) {
        params = { 'date': this.date, 'name': this.name, 'notes': this.notes, 'description': this.description }
      } else {
        params = { 'date': this.date, 'name': this.name, 'notes': this.notes, 'description': this.description, 'image': this.image }
      } 
      let payload = new FormData()
      Object.entries(params).forEach(
        ([key, value]) => payload.append(key, value)
      )
      this.$axios.$patch(`/documents/${this.$route.params.id}`, payload)
        .then(() => {
          this.$router.push(`/documents/${this.$route.params.id}`)
        })
    },
    selectCar: function(event) {
      this.carId = event.target.value
      this.documentableId = event.target.value
    },
    selectMaintenance: function(event) {
      this.maintenanceId = event.target.value
      this.documentableId = event.target.value
    }
  }
}
</script>
