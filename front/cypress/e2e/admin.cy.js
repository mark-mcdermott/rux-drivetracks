/// <reference types="cypress" />

// reset the db: rails db:drop db:create db:migrate db:seed RAILS_ENV=test
// run dev server with test db: CYPRESS=1 bin/rails server -p 3000

describe('Admin login', () => {
  it('Should go to admin show page', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.get('h2').should('contain', 'Michael Scott')
    cy.get('p').should('contain', 'id: 1')
    cy.get('p').should('contain', 'avatar:')
    cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*michael-scott.png/)
    cy.get('p').should('contain', 'admin: true')
    cy.logoutAdmin()
  })
  it('Should contain admin nav', () => {
    cy.loginAdmin()
    cy.get('nav ul.menu li a').should('contain', 'Admin')
    cy.logoutAdmin()
  })
})

describe('Admin nav', () => {
  it('Should work', () => {
    cy.loginAdmin()
    cy.get('nav li a').contains('Admin').click()
    cy.url().should('match', /http:\/\/localhost:3001\/admin/)
    cy.logoutAdmin()
  })
})

describe('Admin page', () => {
  it('Should have correct copy', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.visit('http://localhost:3001/admin')
    cy.url().should('match', /http:\/\/localhost:3001\/admin/)
    cy.get('p').eq(0).invoke('text').should('match', /Number of users: \d+/)
    cy.get('p').eq(1).invoke('text').should('match', /Number of admins: \d+/)
    cy.get('p').eq(2).invoke('text').should('match', /Number of cars: \d+/)
    cy.get('p').eq(3).invoke('text').should('match', /Number of maintenances: \d+/)
    cy.get('p').eq(4).invoke('text').should('match', /Number of documents: \d+/)
    cy.get('p').eq(5).contains('Users')
    cy.get('p').eq(6).contains('Cars')
    cy.get('p').eq(7).contains('Maintenances')
    cy.get('p').eq(8).contains('Documents')
    cy.logoutAdmin()
  })
  it('Should have correct links', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.visit('http://localhost:3001/admin')
    cy.url().should('match', /http:\/\/localhost:3001\/admin/)
    cy.get('p').contains('Users').should('have.attr', 'href', '/users')
    cy.logoutAdmin()
  })
  it('Should have working links', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.visit('http://localhost:3001/admin')
    cy.url().should('match', /http:\/\/localhost:3001\/admin/)
    cy.get('p a').contains('Users').click()
    cy.url().should('match', /http:\/\/localhost:3001\/users/)
    cy.logoutAdmin()
  })
})

describe('Edit user as admin', () => {
  it('Should be successful', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.wait(1000)
    cy.get('h2').children().eq(1).click()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1\/edit/)
    cy.get('p').contains('Name').next('input').clear()
    cy.get('p').contains('Name').next('input').type('name')
    cy.get('p').contains('Email').next('input').clear()
    cy.get('p').contains('Email').next('input').type('name@mail.com')
    cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/dwight-schrute.png')
    cy.get('button').click()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.get('h2').should('contain', 'name')
    cy.get('p').contains('email').should('contain', 'name@mail.com')
    cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*dwight-schrute.png/)
    cy.get('p').should('contain', 'admin: true')
    cy.get('h2').children().eq(1).click()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1\/edit/)
    cy.get('p').contains('Name').next('input').clear()
    cy.get('p').contains('Name').next('input').type('Michael Scott')
    cy.get('p').contains('Email').next('input').clear()
    cy.get('p').contains('Email').next('input').type('michaelscott@dundermifflin.com')
    cy.get('input[type=file]').selectFile('cypress/fixtures/images/office-avatars/michael-scott.png')
    cy.get('button').click()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.get('h2').should('contain', 'Michael Scott')
    cy.get('p').contains('email').should('contain', 'michaelscott@dundermifflin.com')
    cy.get('p').contains('avatar:').next('img').should('have.attr', 'src').should('match', /http.*michael-scott.png/)
    cy.get('p').should('contain', 'admin: true')
    cy.logoutAdmin()
  })
})

describe('Admin /users page', () => {
  it('Should show three users', () => {
    cy.loginAdmin()
    cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
    cy.visit('http://localhost:3001/users')
    cy.url().should('match', /http:\/\/localhost:3001\/users/)
    cy.get('section').children('div').should('have.length', 3)
    cy.logoutAdmin()
  })
})

describe('Admin visiting /cars', () => {

  context('No query string', () => {
    it("Should show all users' cars", () => {
      cy.loginAdmin()
      cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
      cy.visit('http://localhost:3001/cars')
      cy.url().should('match', /http:\/\/localhost:3001\/cars/)
      cy.get('section').children('div').should('have.length', 6)
      cy.get('article').eq(0).find('h2').should('contain', "Michael's Fiat 500")
      cy.get('article').eq(1).find('h2').should('contain', "Michael's Honda Civic")
      cy.get('article').eq(2).find('h2').should('contain', "Jim's Hyundai Elantra")
      cy.get('article').eq(3).find('h2').should('contain', "Jim's Nissan Leaf")
      cy.get('article').eq(4).find('h2').should('contain', "Pam's Scion Xb")
      cy.get('article').eq(5).find('h2').should('contain', "Pam's Toyota Camry")
      cy.logoutAdmin()
    })
  })

  context('?admin=true query string', () => {
    it("Should show all cars", () => {
      cy.loginAdmin()
      cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
      cy.visit('http://localhost:3001/cars?admin=true')
      cy.url().should('match', /http:\/\/localhost:3001\/cars\?admin=true/)
      cy.get('section').children('div').should('have.length', 6)
      cy.logoutAdmin()
    })
  })

  context('user_id=1 query string', () => {
    it("Should show user one's two cars", () => {
      cy.loginAdmin()
      cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
      cy.visit('http://localhost:3001/cars?user_id=1')
      cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=1/)
      cy.get('section').children('div').should('have.length', 2)
      cy.get('article').eq(0).find('h2').should('contain', "Michael's Fiat 500")
      cy.get('article').eq(1).find('h2').should('contain', "Michael's Honda Civic")
      cy.logoutAdmin()
    })
  })

  context('user_id=2 query string', () => {
    it("Should show user two's three cars", () => {
      cy.loginAdmin()
      cy.url().should('match', /http:\/\/localhost:3001\/users\/1/)
      cy.visit('http://localhost:3001/cars?user_id=2')
      cy.url().should('match', /http:\/\/localhost:3001\/cars\?user_id=2/)
      cy.get('section').children('div').should('have.length', 2)
      cy.get('article').eq(0).find('h2').should('contain', "Jim's Hyundai Elantra")
      cy.get('article').eq(1).find('h2').should('contain', "Jim's Nissan Leaf")
      cy.logoutAdmin()
    })
  })
  
})
