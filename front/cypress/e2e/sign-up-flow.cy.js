/// <reference types="cypress" />

// reset the db: db:drop db:create db:migrate db:seed RAILS_ENV=test
// run dev server with test db: CYPRESS=1 bin/rails server -p 3000
describe('Sign Up Flow', () => {
  it('Should redirect to user show page', () => {
    let userId = -1
    cy.visit('http://localhost:3001/sign-up')
    cy.get('p').contains('Name').next('input').type('name')
    cy.get('p').contains('Email').next('input').type('test' + Math.random().toString(36).substring(2, 15) + '@mail.com')
    cy.get('p').contains('Email').next('input').type('test' + Math.random().toString(36).substring(2, 15) + '@mail.com')
    cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/dwight-schrute.png')
    cy.get('p').contains('Password').next('input').type('password')
    cy.get('button').contains('Create User').click()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/\d+/)
    cy.get('h2').should('contain', 'name')
    cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*dwight-schrute.png/)
    cy.url().then(url => {
      userId = url.split('/')[url.split('/').length - 1]
      cy.logout()
      cy.loginAdmin()
      const userShowUrl = `http://localhost:3001/users/${userId}`
      cy.wait(1000)
      cy.visit(userShowUrl)
      const userShowRegex = new RegExp(userShowUrl)
      cy.url().should('match', userShowRegex)
      cy.get('h2').children().eq(2).click() // deletes user
      cy.visit('http://localhost:3001/users/')
      cy.url().should('match', /http:\/\/localhost:3001\/users/)
      cy.get('section').children('div').should('have.length', 3)
      cy.logoutAdmin()
    })    
  })
})
