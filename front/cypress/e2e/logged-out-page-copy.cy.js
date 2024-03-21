/// <reference types="cypress" />

// reset the db: db:drop db:create db:migrate db:seed RAILS_ENV=test
// run dev server with test db: CYPRESS=1 bin/rails server -p 3000
context('Logged Out', () => {
  describe('Homepage Copy', () => {
    it('should find page copy', () => {
      cy.visit('http://localhost:3001/')
      cy.get('main.container')
        .should('contain', 'Drivetracks')
        .should('contain', 'Cloud Car Document Storage')
      cy.get('img').should('have.attr', 'src', '/_nuxt/assets/images/challenger.png')
      cy.get('h3')
        .next('table')
          .within(() => {
            cy.get('th').eq(0).contains('Email')
            cy.get('th').eq(1).contains('Password')
            cy.get('th').eq(2).contains('Notes')
          }) 
    })
  })

  describe('Log In Copy', () => {
    it('should find page copy', () => {
      cy.visit('http://localhost:3001/log-in')
      cy.get('main.container')
        .should('contain', 'Email')
        .should('contain', 'Password')
        .should('contain', 'Log In')
        .should('contain', "Don't have an account")
    })
  })

  describe('Sign Up Copy', () => {
    it('should find page copy', () => {
      cy.visit('http://localhost:3001/sign-up')
      cy.get('main.container')
        .should('contain', 'Name')
        .should('contain', 'Email')
        .should('contain', 'Avatar')
        .should('contain', 'Password')
        .should('contain', 'Create User')
    })
  })
})
