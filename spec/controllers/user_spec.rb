# -*- encoding : utf-8 -*-
require 'spec_helper'

describe Skeleton::Controllers::User do
  let(:json_response) { JSON.parse(last_response.body) }

  before :each do
    Skeleton::User.delete_all
  end

  def app
    Rack::URLMap.new Skeleton.route_map
  end

  it_should_behave_like 'an etag', :user, '/user/:id'

  context 'create' do
    it "should save a complete user" do
      user = FactoryGirl.attributes_for :user, address: FactoryGirl.attributes_for(:address)
      post '/user', user.to_json
      last_response.status.should == 201

      get last_response['location']
      last_response.should be_ok

      saved_user = JSON.parse(last_response.body)['resource']

      saved_user['name'].should == user[:name]
      saved_user['email'].should == user[:email]
      saved_user['cpf'].should == user[:cpf]

      [:street_line1, :street_line2, :street_number, :neighbourhood, :postal_code, :city, :state].each do |field|
        saved_user['address'][field.to_s].should == user[:address][field]
      end
    end

    it 'should save an ess imported user' do
      imported_data = {
        gender: 'M',
        rg: '1234567890',
        inscricao_estadual: '1234567890',
        user_type: 'F',
        date_of_birth: '28/02/1986',
        phone_number_area_code: '51',
        phone_number: '1234-5678',
        branch_line_number: '51',
        cellphone_number: '12345-6789',
        deactivated: false,
        deactivation_date: DateTime.parse('2012/06/06').to_s,
        last_version_id: '1',
        version: '1',
        created_at: DateTime.parse('2012/06/06').to_s,
        updated_at: DateTime.parse('2012/06/06').to_s
      }

      user = FactoryGirl.attributes_for(:user, {
        address: FactoryGirl.attributes_for(:address),
        external_id: 123,
        ess_imported_data: imported_data
      })

      post '/user', user.to_json
      last_response.status.should == 201

      get last_response['location']
      last_response.should be_ok

      saved_user = JSON.parse(last_response.body)['resource']
      saved_user['external_id'].should == 123
      imported_data.keys.each do |field|
        saved_user['ess_imported_data'][field.to_s].should == user[:ess_imported_data][field]
      end
    end

    it "should save salt when importing user from iba1" do
      user = FactoryGirl.attributes_for :user, salt: 'salt_from_iba_one', ess_imported_data: { gender: 'M' }

      post '/user', user.to_json

      last_response.status.should == 201

      Skeleton::User.last.salt.should == 'salt_from_iba_one'
    end

    it "should not save the card for complete user" do
      user = FactoryGirl.attributes_for :user, address: FactoryGirl.attributes_for(:address), card: FactoryGirl.build(:card)
      post '/user', user.to_json
      last_response.status.should == 201

      Skeleton::User.last.card.should be_nil
    end

    context 'with errors on the mongo model' do
      it "should return the model errors if any" do
        user_attributes = FactoryGirl.attributes_for(:adult_user, password: 'f')

        post '/user', user_attributes.to_json
        last_response.status.should == 422

        response_hash = JSON.parse(last_response.body)

        returned_user = response_hash['resource']
        returned_user['errors']['password'].should == ["A senha deve conter pelo menos 8 caracteres, incluindo letras e números."]
        returned_user['password'].should == nil
      end
    end

    context 'with errors on the client model' do
      it "should return the model errors if any" do
        user_attributes = FactoryGirl.attributes_for(:adult_user)
        user_attributes[:name] = nil

        post '/user', user_attributes.to_json
        last_response.status.should == 422

        response_hash = JSON.parse(last_response.body)
        returned_user = response_hash['resource']

        returned_user['errors']['name'].should_not be_nil
        returned_user['errors']['name'].should_not be_empty
      end
    end

    it "should use only user properties to create a new User" do
      user_attributes = FactoryGirl.attributes_for(:user)

      post '/user', user_attributes.to_json

      user = Skeleton::User.last
      last_response.status.should == 201
      last_response.location.should == "/user/#{user._id}"

      last_response.body.should be_empty
    end

    it 'should respond with a 422 if no user params are provided' do
      post '/user', {}.to_json
      last_response.status.should == 422
    end

    context 'external_id duplication' do
      it 'should return a 409 if a user is imported with existing external id' do
        Skeleton.config.redis.set(:last_ess_user_id, 1)
        user = FactoryGirl.create(:user, name: 'Booga Booga',external_id: '100')
        another_user = FactoryGirl.attributes_for(:user, name: 'Yola ola',external_id: '100')

        post '/user', another_user.to_json
        last_response.status.should == 409
        last_response.body.should == {errors: I18n.t('external_id.present')}.to_json
        Skeleton.config.redis.get(:last_ess_user_id).should == "1"
      end
    end
  end

  context :put do
    it "should return 400 if no data is sent" do
      put '/user/12312'
      last_response.status.should == 400
    end

    it "should return 404 if id is not in the correct format" do
      put '/user/1212', {}.to_json
      last_response.status.should == 404
    end

    it "should return 404 if admin could not be found" do
      dummy_id = Moped::BSON::ObjectId.new

      put "/user/#{dummy_id}", {}.to_json

      last_response.status.should == 404
    end

    it "should return 422 if data passed could not be parsed" do
      user = FactoryGirl.create(:user)

      put "/user/#{user._id}", {resource: 1}.to_json
      last_response.status.should == 422
    end

    it "should update an existing user (if found) based on email parameter passed" do
      user = FactoryGirl.create(:user)
      name = 'new_name'

      resource = user.attributes.dup
      resource.delete('_id')
      resource.delete('password')
      resource['name'] = name

      put "/user/#{user._id}", resource.to_json
      last_response.status.should == 200
      Skeleton::User.find(user._id).name.should == name
    end

    it "should not save the card for user when updating" do
      user = FactoryGirl.create(:user)
      name = 'new_name'

      resource = user.attributes.dup
      resource.delete('_id')
      resource.delete('password')
      resource['name'] = name
      resource['card'] = FactoryGirl.build(:card).to_json

      put "/user/#{user._id}", resource.to_json
      last_response.status.should == 200
      Skeleton::User.find(user._id).name.should == name

      Skeleton::User.last.card.should be_nil
    end

    it "should never update salt if not IBA1 user" do
      user = FactoryGirl.create(:user)

      user.should_not be_iba1_user

      resource = user.attributes.dup
      resource.delete('_id')
      resource['salt'] = 'troll'

      put "/user/#{user._id}", resource.to_json

      last_response.status.should == 200
      Skeleton::User.find(user._id).salt.should_not == 'troll'
    end

    it "should never update salt if password not provided" do
      user = FactoryGirl.create(:user)

      user.should_not be_iba1_user

      resource = user.attributes.dup
      resource.delete('_id')
      resource.delete('password')
      resource['salt'] = 'troll'

      put "/user/#{user._id}", resource.to_json

      last_response.status.should == 200
      Skeleton::User.find(user._id).salt.should_not == 'troll'
    end

    it "should update password and salt for IBA1 user import" do
      user = FactoryGirl.create(:user, ess_imported_data: { gender: 'M' })

      resource = user.attributes.dup
      resource.delete('_id')
      resource['password'] = 'password from iba1'
      resource['salt'] = 'salt from iba1'

      put "/user/#{user._id}", resource.to_json

      last_response.status.should == 200
      user.reload
      user.password.should == 'password from iba1'
      user.salt.should == 'salt from iba1'
    end

    it "should not fail if the supplied password is nil" do
      user = FactoryGirl.create(:user)

      resource = user.attributes.dup
      resource.delete('_id')
      resource['password'] = nil

      put "/user/#{user._id}", resource.to_json
      last_response.status.should == 200
    end

    context 'when updating password' do
      let(:old_password) { 'old_p@ssw0rd' }
      let(:new_password) { 'new_p@ssw0rd' }

      before do
        Timecop.freeze

        SecureRandom.stub(:uuid).exactly(2).times.and_return('random')

        salt = "random#{Time.now.to_i}".hash
        BCrypt::Password.stub(:create).with("#{salt}:#{old_password}").and_return('encrypted_old_password')
        BCrypt::Password.stub(:create).with("#{salt}:#{new_password}").and_return('encrypted_new_password')
      end

      it "should encrypt and save new password" do
        user = FactoryGirl.create(:user, password: old_password)

        resource = user.attributes.dup
        resource.delete('_id')
        resource['password'] = new_password

        put "/user/#{user._id}", resource.to_json

        last_response.status.should == 200
        Skeleton::User.find(user._id).password.should == 'encrypted_new_password'
      end

      it "should encrypt password even if user was imported from iba1" do
        user = FactoryGirl.create(:user, password: old_password, ess_imported_data: {})

        resource = user.attributes.dup
        resource.delete('_id')
        resource['password'] = new_password

        put "/user/#{user._id}", resource.to_json

        last_response.status.should == 200
        Skeleton::User.find(user._id).password.should == 'encrypted_new_password'
      end

      it 'should NOT log the plain password' do
        user = FactoryGirl.create(:user, password: old_password)
        resource = user.attributes.dup
        resource.delete('_id')
        resource['password'] = new_password

        logs = []
        logger = double("Logger")
        Skeleton::Controllers::User.any_instance.stub(:logger).and_return(logger)
        logger.stub(:info) { |message| logs << message }

        put "/user/#{user._id}", resource.to_json

        last_response.status.should == 200
        logs.each { |log| log.should_not include('p@ssw0rd') }
      end
    end

    context "update email" do
      it "should update an existing user's email address" do
        user = FactoryGirl.create(:user, email: "oldemail@example.com")
        user.signup!
        user.forgot_password_click!

        put "/user/change_email/#{user._id}", {'email' => "newemail@example.com"}.to_json

        last_response.status.should == 200

        Skeleton::User.find(user._id).tap do |u|
          u.email.should == "newemail@example.com"
          u.verification_token.should_not == user.verification_token
          u.forgot_password_token.should be_nil
        end
      end

      it 'returns the rollback token in the response body' do
        random_mock = 'random_mock'
        digest_mock = 'digest_mock'

        allow(SecureRandom).to receive(:base64) { random_mock }
        allow(Digest).to receive(:bubblebabble).with(random_mock) { digest_mock }

        user = create(:user, email: 'oldemail@example.com')
        user.signup!
        user.forgot_password_click!

        put "/user/change_email/#{user._id}", { 'email' => 'newemail@example.com' }.to_json

        body = JSON.parse(last_response.body)
        expect(body['rollback_token']).to eq digest_mock
      end

      it "should not update the existing user's email if incoming is invalid" do
        user = FactoryGirl.create(:user, email: "oldemail@example.com")
        user.signup!
        user.forgot_password_click!

        put "/user/change_email/#{user._id}", {}.to_json

        last_response.status.should == 422
        JSON.parse(last_response.body)['errors']['email'].should_not be_nil

        Skeleton::User.find(user._id).should == user
      end

      it "should not update the existing user's email if incoming is same as current" do
        user = FactoryGirl.create(:user, email: "existing-email@example.com")
        user.signup!
        user.forgot_password_click!

        put "/user/change_email/#{user._id}", {'email' => "existing-email@example.com"}.to_json

        last_response.status.should == 422
        JSON.parse(last_response.body)['errors']['email'].should_not be_nil
        JSON.parse(last_response.body)['errors']['email'].should == ["O novo email não deve ser igual ao email atual."]
        Skeleton::User.find(user._id).should == user
      end

      it 'fails when user is not found' do
        put "/user/change_email/dont-know-the-user", { 'email' => 'newemail@example.com' }.to_json

        expect(last_response.status).to eq 404
      end
    end

    context 'rolling back a changed email' do
      before do
        @user = create(:user, email: 'oldemail@iba.com')
        user_email_change = Skeleton::UserEmailChange.new(@user)
        user_email_change.change_email('newemail@iba.com')
        @token = user_email_change.rollback_token
      end

      it 'rolls email back when the token is valid' do
        put "/user/rollback_changed_email/#{@user._id}", { 'rollback_token' => @token }.to_json

        expect(last_response.status).to eq 200

        expect(JSON.parse(last_response.body)['resource']['email']).to eq('oldemail@iba.com')
      end

      it 'fails when user is not found' do
        put "/user/rollback_changed_email/invalid_user", { 'rollback_token' => @token }.to_json

        expect(last_response.status).to eq 404
      end

      it 'fails when rollback token is invalid' do
        put "/user/rollback_changed_email/#{@user._id}", { 'rollback_token' => 'invalid token' }.to_json

        expect(last_response.status).to eq 422
      end

      it 'fails when rollback token got expired' do
        Timecop.travel(8.days.from_now) do
          put "/user/rollback_changed_email/#{@user._id}", { 'rollback_token' => @token }.to_json
        end

        expect(last_response.status).to eq 422
      end
    end

    it "should update an existing users address attributes" do
      user = FactoryGirl.create(:user_with_billing_details)
      city = 'Vegas'

      put "/user/#{user._id}", {'address' => {'city' => city}}.to_json

      last_response.should be_ok
      Skeleton::User.find(user._id).address.city.should == city
    end

    it "should not update user card field" do
      user = FactoryGirl.create(:user_with_billing_details)
      user.verify!
      card = FactoryGirl.build(:card)

      put "/user/#{user._id}", {'card' => card}.to_json

      last_response.should be_ok
      Skeleton::User.find(user._id).card.should be_nil
    end

    it "should fail the update if passed data is invalid" do
      user = FactoryGirl.create(:user_with_billing_details)
      invalid_city = ''

      put "/user/#{user._id}", {'address' => {'city' => invalid_city}}.to_json

      last_response.status.should == 422
      response_hash = JSON.parse(last_response.body)

      returned_user = response_hash['resource']
      returned_user['errors'].should_not be_empty
    end
  end

  context 'changing the password' do
    let(:user) { FactoryGirl.create(:user, password: 'password123') }

    it 'updates the user password if the given one is correct' do
      put "/user/#{user.id}/change_password", { current_password: 'password123', new_password: 'newpassword123' }.to_json
      expect(last_response.status).to eq 200

      user.reload
      expect(user.valid_password?('newpassword123')).to be_true
    end

    it 'does not update the password if given one is incorrect' do
      put "/user/#{user.id}/change_password", { current_password: 'incorrect', new_password: 'p0wn3d' }.to_json
      expect(last_response.status).to eq 422

      errors = JSON.parse(last_response.body)
      expect(errors['resource']['errors']).to eq({
        'password' => ['Senha incorreta.']
      })

      user.reload
      expect(user.valid_password?('password123')).to be_true
    end

    it 'validates password format when changing password' do
      put "/user/#{user.id}/change_password", { current_password: 'password123', new_password: 'abc' }.to_json
      expect(last_response.status).to eq 422

      errors = JSON.parse(last_response.body)
      expect(errors['resource']['errors']).to eq({
        'password' => ['A senha deve conter pelo menos 8 caracteres, incluindo letras e números.']
      })

      user.reload
      expect(user.valid_password?('password123')).to be_true
    end
  end

  context "search" do
    it 'should return content type' do
      get '/search/user'
      last_response.should be_ok
      last_response.content_type.should == 'application/vnd.iba.skeleton.user.search_results+json;charset=utf-8'
    end

    it "should return all users if no parameters passed" do
      2.times { FactoryGirl.create(:user) }
      get "/search/user"
      last_response.should be_ok
      json_response['search_results'].length.should == 2
      json_response['links'].should_not be_empty
      json_response['meta'].should == {'total_results' => 2, 'total_pages' => 1}
    end

    it 'should search users by external id' do
      2.times { FactoryGirl.create(:user) }
      user = FactoryGirl.create(:user, external_id: 100)
      get "/search/user", external_id: 100

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'].first['href'].should == "/user/#{user._id}"
    end

    it "should search users by email" do
      users = 2.times.collect { FactoryGirl.create(:user) }
      search_user = users.last
      get "/search/user", email: search_user.email

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'][0]['href'].should == "/user/#{search_user._id}"
    end

    it "should search users by email case insensitive" do
      users = 2.times.collect { FactoryGirl.create(:user) }
      search_user = users.last
      get "/search/user", email: search_user.email.upcase

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'][0]['href'].should == "/user/#{search_user._id}"
    end

    it "should search users by name" do
      users = 2.times.collect { FactoryGirl.create(:user) }
      search_user = users.last
      get "/search/user", name: search_user.name

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'][0]['href'].should == "/user/#{search_user._id}"
    end

    it "should search users by verification token" do
      users = 2.times.collect do
        user = FactoryGirl.build(:user)
        user.signup!
        user
      end
      search_user = users.last
      get "/search/user", verification_token: search_user.verification_token

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'][0]['href'].should == "/user/#{search_user._id}"
    end

    it "should search users by forgot password token" do
      users = 2.times.collect do
        user = FactoryGirl.build(:user)
        user.signup!
        user.forgot_password_click!
        user
      end
      search_user = users.last
      get "/search/user", forgot_password_token: search_user.forgot_password_token

      last_response.should be_ok
      JSON.parse(last_response.body)['search_results'].length.should == 1

      JSON.parse(last_response.body)['search_results'][0]['href'].should == "/user/#{search_user._id}"
    end

    it "should not exclude nil parameters from the search criteria" do
      FactoryGirl.create :user
      get '/search/user', email: nil
      last_response.status.should == 200
      JSON.parse(last_response.body)['search_results'].should == []
    end

    it "should search by name and get all the matches" do
      FactoryGirl.create(:user)
      users = 2.times.collect { FactoryGirl.create(:user, name: "Rajini #{rand(100)}") }
      get "/search/user", name: "Rajini"
      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 2
    end

    it "should search by email and get the match" do
      FactoryGirl.create(:user, email: 'gmail@rajini.com')

      get "/search/user", email: "gmail@rajini.com"

      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 1
    end

    it "should search by cpf" do
      2.times { FactoryGirl.create :user }
      user = FactoryGirl.create :user_with_billing_details
      get "/search/user", cpf: user.cpf
      last_response.status.should == 200
      response = JSON.parse(last_response.body)

      response['search_results'].length.should == 1
      response['search_results'][0]['href'].should == "/user/#{user._id}"
    end

    it "should search by gender" do
      user1= FactoryGirl.create(:user, gender: 'M')
      user2= FactoryGirl.create(:user, gender: 'F')
      get "/search/user", gender: 'M'
      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 1
      response['search_results'][0]['href'].should == "/user/#{user1._id}"
    end

    it "should search by state" do
      user1 = FactoryGirl.create(:user , address: FactoryGirl.build(:address, state: 'SP'))
      user2 = FactoryGirl.create(:user , address: FactoryGirl.build(:address, state: 'CP'))
      get "/search/user" , address_state: 'SP'
      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 1
      response['search_results'][0]['href'].should == "/user/#{user1._id}"
    end

    it "should search by user who opted for newsletter " do
      user1 = FactoryGirl.create(:user, address: FactoryGirl.build(:address))

      user2 = FactoryGirl.create(:user, newsletters: [
        FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
        FactoryGirl.build(:newsletter, type: 'HP', accepted: true)
      ])

      user3 = FactoryGirl.create(:user, newsletters: [
        FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
        FactoryGirl.build(:newsletter, type: 'HP', accepted: false)
      ])

      user4 = FactoryGirl.create(:user, newsletters: [
        FactoryGirl.build(:newsletter, type: 'iba', accepted: true),
        FactoryGirl.build(:newsletter, type: 'HP', accepted: true)
      ])

      get "/search/user" , newsletters_opted: 'true'

      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 2
      search_results = response['search_results'].map {|user| user["href"]}
      search_results.should include "/user/#{user2._id}"
      search_results.should include "/user/#{user4._id}"
    end

    it "should search by creation date range" do
      user1 = FactoryGirl.create(:user , address: FactoryGirl.build(:address))
      user2 = FactoryGirl.create(:user , address: FactoryGirl.build(:address))
      user2.created_at = 1.day.since.end_of_day
      user2.save!

      get "/search/user", {'greater_than[created_at]' => Date.today.strftime('%Y-%m-%d'),'less_than[created_at]' => Date.today.next_day.strftime('%Y-%m-%d') }

      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 1
      response['search_results'][0]['href'].should == "/user/#{user1._id}"
    end

    it "should search by multiple clause" do
      user1 = FactoryGirl.create(:user ,gender: 'M', address: FactoryGirl.build(:address, state: 'SP'))
      user2 = FactoryGirl.create(:user,gender: 'M' ,address: FactoryGirl.build(:address, state: 'SP'),
                                 newsletters: [FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
                                               FactoryGirl.build(:newsletter, type: 'HP', accepted: true)])
      user2.created_at = 1.day.since.end_of_day;user2.save!

      user3= FactoryGirl.create(:user, gender: 'F',address: FactoryGirl.build(:address, state: 'PN'),
                                newsletters: [FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
                                              FactoryGirl.build(:newsletter, type: 'HP', accepted: false)])

      user4= FactoryGirl.create(:user,gender: 'M',address: FactoryGirl.build(:address, state: 'SP'),
                                newsletters: [FactoryGirl.build(:newsletter, type: 'iba', accepted: true),
                                              FactoryGirl.build(:newsletter, type: 'HP', accepted: true)])

      user3= FactoryGirl.create(:user, gender: 'M',address: FactoryGirl.build(:address, state: 'PN'),
                                newsletters: [FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
                                              FactoryGirl.build(:newsletter, type: 'HP', accepted: false)])

      user5= FactoryGirl.create(:user,gender: 'M',address: FactoryGirl.build(:address, state: 'SP'),
                                newsletters: [FactoryGirl.build(:newsletter, type: 'iba', accepted: false),
                                              FactoryGirl.build(:newsletter, type: 'HP', accepted: true)])

      get "/search/user", {'greater_than[created_at]' => Date.today.strftime('%Y-%m-%d'),'less_than[created_at]' => Date.today.next_day.strftime('%Y-%m-%d'),
                           newsletters_opted: 'true',address_state: 'SP',gender: 'M' }

      last_response.status.should == 200
      response = JSON.parse(last_response.body)
      response['search_results'].length.should == 2
      search_results = response['search_results'].map {|user| user["href"]}
      search_results.should include "/user/#{user4._id}"
      search_results.should include "/user/#{user5._id}"

    end

  end

  context "newsletters" do

    it "should add the newsletter subscription " do
      user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
      newsletter_attributes = FactoryGirl.attributes_for(:newsletter, type: "type1", accepted: false)
      post "/user/#{user._id}/newsletters", newsletter_attributes.to_json

      last_response.status.should == 200

      user_from_db = Skeleton::User.find user._id
      user_from_db.newsletters.count.should == 2
      user_from_db.newsletters.last.type.should == "type1"
      user_from_db.newsletters.last.accepted.should be_false
    end


    it "should return 422 error if type not given " do
      user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
      newsletter_attributes = FactoryGirl.attributes_for(:newsletter, type: "type1", accepted: false)
      newsletter_attributes.delete :type

      post "/user/#{user._id}/newsletters", newsletter_attributes.to_json
      last_response.status.should == 422
      JSON.parse(last_response.body)[1]['errors']['type'][0].should == I18n.t('mongoid.errors.models.skeleton/newsletter.attributes.type.blank')

    end

    it "should return 422 error if accepted not given " do
      user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
      newsletter_attributes = FactoryGirl.attributes_for(:newsletter, type: "type1", accepted: false)
      newsletter_attributes.delete :accepted

      post "/user/#{user._id}/newsletters", newsletter_attributes.to_json

      last_response.status.should == 422
      JSON.parse(last_response.body)[1]['errors']['accepted'][0].should == I18n.t('mongoid.errors.models.skeleton/newsletter.attributes.accepted.blank')

    end

    it "should return 404 error if user does not exist" do
      dummy_id = Moped::BSON::ObjectId.new
      newsletter_attributes = FactoryGirl.attributes_for(:newsletter, type: "type1", accepted: false)

      post "/user/#{dummy_id}/newsletters", newsletter_attributes.to_json

      last_response.status.should == 404

    end

    it "should contains the links for newsletters" do
      user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
      get "/user/#{user._id}"

      last_response.should be_ok
      last_response.body.should have_link('self', "/user/#{user._id}")
      last_response.body.should have_link('newsletters', "/user/#{user._id}/newsletters")
    end


    it "should get the newsletters for a user" do
      user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
      get "/user/#{user._id}/newsletters"

      last_response.should be_ok
      response = JSON.parse(last_response.body)
      response[0]['type'].should == "iba"
      response[0]['accepted'].should == true
    end


    context "update" do
      it "should update existing newsletter with the new one" do
        user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
        newsletter_attributes = FactoryGirl.attributes_for(:newsletter, accepted: false)
        put "/user/#{user._id}/newsletters", newsletter_attributes.to_json

        last_response.status.should == 200

        user_from_db = Skeleton::User.find user._id
        user_from_db.newsletters.count.should == 1
        user_from_db.newsletters.first.accepted.should be_false
      end

      it "should return 400 if no data is sent" do
        user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
        put "/user/#{user._id}/newsletters"
        last_response.status.should == 400
      end

      it "should return 404 if id is not in the correct format" do
        put '/user/1212/newsletters', {}.to_json
        last_response.status.should == 404
      end

      it "should return 404 if user could not be found" do
        dummy_id = Moped::BSON::ObjectId.new

        put "/user/#{dummy_id}/newsletters", {}.to_json

        last_response.status.should == 404
      end

      it "should return 400 if data passed could not be parsed" do
        user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)

        put "/user/#{user._id}/newsletters", {invalid: 1}.to_json
        last_response.status.should == 400
      end

      it "should return 422 if invalid newsletter is passed" do
        user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions)
        invalid_newsletter_attributes = FactoryGirl.attributes_for(:newsletter, accepted: false)
        invalid_newsletter_attributes.delete :accepted

        put  "/user/#{user._id}/newsletters", invalid_newsletter_attributes.to_json
        last_response.status.should == 422
        JSON.parse(last_response.body)[0]['errors']['accepted'][0].should == I18n.t('mongoid.errors.models.skeleton/newsletter.attributes.accepted.blank')
      end
    end
  end

  context "adult confirmation update" do

    context "update" do
      it "should update user to confirmed adult " do
        user = FactoryGirl.create(:user)
        time_now = DateTime.now
        Timecop.freeze(time_now.to_s)
        put "/user/set_adult/#{user._id}"

        last_response.status.should == 200

        user_from_db = Skeleton::User.find user._id
        user_from_db.adult.confirmed.should be_true
        user_from_db.adult.updated_at.should == time_now.to_s
        Timecop.return
      end

      it "should return 400 if user could not be found" do
        put "/user/set_adult/11"
        last_response.status.should == 401
      end
    end
  end


  context "terms conditions" do
    let(:user) { create(:user_with_newsletters_and_terms_conditions) }

    it 'adds the terms and conditions' do
      terms_conditions_attributes = attributes_for(:terms_conditions, source: 'iba_test', type: 'type1')

      post "/user/#{user.id}/terms_conditions", terms_conditions_attributes.to_json

      expect(last_response.status).to eq 200

      user_from_db = Skeleton::User.find(user.id)
      terms_and_conditions = user_from_db.terms_conditions
      expect(terms_and_conditions.count).to eq 2
      expect(terms_and_conditions.last.source).to eq 'iba_test'
      expect(terms_and_conditions.last.type).to eq 'type1'
    end

    it 'returns 422 if invalid terms and conditions' do
      terms_conditions_attributes = attributes_for(:terms_conditions, source: '', type: '')

      post "/user/#{user.id}/terms_conditions", terms_conditions_attributes.to_json

      expect(last_response.status).to eq 422
      errors = json_response[1]['terms_condition']['errors']
      expect(errors['type']).to include I18n.t('mongoid.errors.models.skeleton/terms_conditions.attributes.type.blank')
      expect(errors['source']).to include I18n.t('mongoid.errors.models.skeleton/terms_conditions.attributes.source.blank')
    end

    it 'returns 404 if user does not exist' do
      post '/user/not_found/terms_conditions', {}

      expect(last_response.status).to eq 404
    end

    it 'returns terms and conditions for a user' do
      get "/user/#{user.id}/terms_conditions"

      expect(last_response.status).to eq 200
      expect(json_response[0]['terms_condition']['type']).to eq 'type 1'
      expect(json_response[0]['terms_condition']['source']).to eq 'iba'
    end

    it 'returns relation links to terms and conditions' do
      get "/user/#{user.id}"

      expect(last_response).to be_ok
      expect(last_response.body).to have_link('self', "/user/#{user.id}")
      expect(last_response.body).to have_link('terms_conditions', "/user/#{user.id}/terms_conditions")
    end
  end

  context 'GET a user by its id' do
    let(:user_id) { 'C01DC0FFEE' }

    context 'non-existing user' do
      before do
        Skeleton::User.should_receive(:find)
                      .with(user_id)
                      .and_raise(Mongoid::Errors::DocumentNotFound.allocate)
      end

      it 'returns a 404' do
        get "/user/#{user_id}"
        last_response.status.should == 404
      end
    end

    context 'existing user' do
      let(:user) {
        FactoryGirl.build(:user,
                          source: 'source1',
                          source_marketing: 'le marketing source')
      }

      before do
        Skeleton::User.should_receive(:find).with(user_id).and_return(user)
      end

      it 'returns the JSON resource of that user' do
        get "/user/#{user_id}"
        last_response.should be_ok

        resource = JSON.parse(last_response.body)['resource']
        resource['source'].should == 'source1'
        resource['source_marketing'].should == 'le marketing source'
      end
    end
  end

  context 'show' do
    context 'found' do
      before do
        @user = FactoryGirl.create(:user, address: FactoryGirl.build(:address))
        @iba1_user = FactoryGirl.create(:user_with_newsletters_and_terms_conditions, address: FactoryGirl.build(:address), ess_imported_data: FactoryGirl.build(:ess_imported_data))
      end

      it 'should find an imported user from iba1 by URI' do

        get "/user/#{@iba1_user._id}"

        last_response.should be_ok

        # FIXME: all those fields are being tested here, even
        # when they are not necessarily related to iba1. It'd
        # better to test them somewhere else.

        JSON.parse(last_response.body)['resource'].should == {
            "name" => @iba1_user.name,
            "email" => @iba1_user.email,
            "gender" => @iba1_user.gender,
            "dob" => @iba1_user.dob,
            "phone_number" => @iba1_user.phone_number,
            "verification_token" => @iba1_user.verification_token,
            "forgot_password_token" => @iba1_user.forgot_password_token,
            "save_card_link_order_id" => @user.save_card_link_order_id,
            "social_account_link" => nil,
            "social_uid" => nil,
            "adobe_adept_uuid" => nil,
            "source" => @user.source,
            'source_marketing' => @user.source_marketing,
            "external_id" => @iba1_user.external_id,
            "cpf" => @iba1_user.cpf,
            "crp_id" => @iba1_user.crp_id,
            "status" => @iba1_user.state,
            "updated_by" => @iba1_user.updated_by,
            "billing_details_complete" => @iba1_user.billing_details_complete?,
            "errors" => {},
            "created_at" => @user.created_at.iso8601,
            "updated_at" => @user.updated_at.iso8601,
            "is_adult" => @user.is_adult?,
            "ess_imported_data" => {
                "gender" => @iba1_user.ess_imported_data.gender,
                "cnpj" => @iba1_user.ess_imported_data.cnpj,
                "rg" => @iba1_user.ess_imported_data.rg,
                "inscricao_estadual" => @iba1_user.ess_imported_data.inscricao_estadual,
                "user_type" => @iba1_user.ess_imported_data.user_type,
                "date_of_birth" => @iba1_user.ess_imported_data.date_of_birth,
                "phone_number_area_code" => @iba1_user.ess_imported_data.phone_number_area_code,
                "phone_number" => @iba1_user.ess_imported_data.phone_number,
                "branch_line_number" => @iba1_user.ess_imported_data.branch_line_number,
                "cellphone_number" => @iba1_user.ess_imported_data.cellphone_number,
                "cellphone_area_code" => @iba1_user.ess_imported_data.cellphone_area_code,
                "simplificado" => @iba1_user.ess_imported_data.simplificado,
                "deactivated" => @iba1_user.ess_imported_data.deactivated,
                "deactivation_date" => @iba1_user.ess_imported_data.deactivation_date,
                "last_version_id" => @iba1_user.ess_imported_data.last_version_id,
                "version" => @iba1_user.ess_imported_data.version,
                "created_at" => @iba1_user.ess_imported_data.created_at,
                "updated_at" => @iba1_user.ess_imported_data.updated_at
            },
            "newsletters" => [{
                "accepted"   => @iba1_user.newsletters.first.accepted,
                "type"       => @iba1_user.newsletters.first.type,
                "created_at" => @iba1_user.newsletters.first.created_at.to_s,
                "updated_at" => @iba1_user.newsletters.first.updated_at.to_s
             }],
            "terms_conditions" => [{
               "source"        => @iba1_user.terms_conditions.first.source,
               "type"          => @iba1_user.terms_conditions.first.type,
               "created_at"    => @iba1_user.terms_conditions.first.created_at.to_s
             }],
            "address" => {
                "street_line1" => @user.address.street_line1,
                "street_line2" => @user.address.street_line2,
                "street_number" => @user.address.street_number,
                "neighbourhood" => @user.address.neighbourhood,
                "postal_code" => @user.address.postal_code,
                "city" => @user.address.city,
                "state" => @user.address.state,
                "errors" => {}
            }
        }

        last_response.body.should have_link('self', "/user/#{@iba1_user._id}")
        last_response.body.should have_link('generate_forgot_password_token', "/user/generate_forgot_password_token")
        last_response.body.should have_link('verify_password', "/user/#{@iba1_user._id}/verify_password")
      end

      it 'should find a signed up user by URI' do
        @user.signup!

        get "/user/#{@user._id}"

        last_response.should be_ok

        last_response.body.should have_link('self', "/user/#{@user._id}")
        last_response.body.should have_link('generate_forgot_password_token', "/user/generate_forgot_password_token")
        last_response.body.should have_link('verify', "/user/verify/#{@user.verification_token}")
        last_response.body.should have_link('verify_password', "/user/#{@user._id}/verify_password")
      end

      it 'includes a link to the save_card action to a verified user' do
        @user.signup!
        @user.verify!

        get "/user/#{@user._id}"

        expect(last_response.body).to have_link('save_card', "/user/#{@user._id}/card")
      end

      it 'includes a link to the save_card action even to an unverified user' do
        @user.signup!

        get "/user/#{@user._id}"

        expect(last_response.body).to have_link('save_card', "/user/#{@user._id}/card")
      end

      it 'has action links for an user' do
        @user.signup!
        @user.verify!
        @user.address = FactoryGirl.build(:address)
        @user.card = FactoryGirl.build(:card)
        @user.save_card!

        get "/user/#{@user._id}"

        last_response.should be_ok
        last_response.body.should have_link('self', "/user/#{@user._id}")
        last_response.body.should have_link('generate_forgot_password_token', "/user/generate_forgot_password_token")
        last_response.body.should have_link('card', "/user/#{@user._id}/card")
        last_response.body.should have_link('verify_password', "/user/#{@user._id}/verify_password")
        last_response.body.should have_link('save_card', "/user/#{@user._id}/card")
      end

      it 'should find a forgotten password user by URI' do
        @user.forgot_password_click!

        get "/user/#{@user._id}"

        last_response.should be_ok
        last_response.body.should have_link('self', "/user/#{@user._id}")
        last_response.body.should have_link('reset_forgotten_password', /\/user\/reset_forgotten_password/)
        last_response.body.should have_link('verify_password', "/user/#{@user._id}/verify_password")
      end
    end
  end

  describe 'generate temporary password' do
    let(:user) { double(Skeleton::User, temporary_password: stub )}
    subject { post '/user/123/generate_temporary_password'}

    context 'when user exists' do
      before { Skeleton::User.stub(:find).with('123').and_return(user)}

      its(:status) { should eql 201 }
    end

    context 'when user not exists' do
      before { Skeleton::User.stub(:find).with('123').and_return(nil)}

      its(:status) { should eql 404 }
    end
  end
end
