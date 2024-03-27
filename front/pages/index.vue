<template>
  <main class="home container">
    <h1>Drivetracks</h1>
    <p class="subtitle">Cloud Car Document Storage</p>
    <img class="challenger" :src="require(`@/assets/images/challenger.png`)" />

    <h3 class="small-bottom-margin">User Logins</h3>
    <table class="half-width">
      <tr><th>Email</th><th>Password</th><th>Notes</th></tr>
      <tr><td>michaelscott@dundermifflin.com</td><td>password</td><td>(admin)</td></tr>
      <tr><td>jimhalpert@dundermifflin.com</td><td>password</td><td></td></tr>
      <tr><td>pambeesly@dundermifflin.com</td><td>password</td><td></td></tr>
    </table>
    
    <p class="big-bottom-margin">
      <NuxtLink to="/log-in" role="button" class="secondary">Log In</NuxtLink> 
      <NuxtLink to="/sign-up" role="button" class="contrast outline">Sign Up</NuxtLink>
    </p>    
  </main>
</template>

<script>
export default { auth: false }
</script>
