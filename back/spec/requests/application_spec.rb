# frozen_string_literal: true

require 'rails_helper'
require 'spec_helper'

RSpec.describe '/me', type: :request do
  fixtures :users
  let(:valid_headers) { { Authorization: "Bearer #{@token}" } }
  let(:invalid_token_header) { { Authorization: 'Bearer xyz' } }
  let(:poorly_formed_header) { { Authorization: "Bear #{@token}" } }

  before :all do
    @token = token_from_email_password('michaelscott@dundermifflin.com', 'password')
  end

  describe 'GET /me' do
    context 'without auth header' do
      it 'returns http success' do
        get '/me'
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with invalid token header' do
      it 'returns http success' do
        get '/me', headers: invalid_token_header
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with valid token, but poorly formed auth header' do
      it 'returns http success' do
        get '/me', headers: poorly_formed_header
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with valid auth header' do
      it 'returns http success' do
        get '/me', headers: valid_headers
        expect(response).to have_http_status(:success)
      end
    end
  end
end
