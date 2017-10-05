# -*- encoding : utf-8 -*-
require 'spec_helper'

describe Skeleton::User do

  let(:user) { FactoryGirl.build(:user) }

  def mock_password(orig_pwd, encrypted_pwd)
    SecureRandom.should_receive(:uuid).and_return("random")
    salt = "random#{Time.now.to_i}".hash
    BCrypt::Password.should_receive(:create).with("#{salt}:#{orig_pwd}").and_return(encrypted_pwd)
  end

  def mock_token
    random_mock = 'random_mock'
    digest_mock = 'digest_mock'

    allow(SecureRandom).to receive(:base64) { random_mock }
    allow(Digest).to receive(:bubblebabble).with(random_mock) { digest_mock }

    digest_mock
  end

  it { expect(subject).to be_timestamped_document }
  it { expect(subject).to have_field(:name).of_type(String) }
  it { expect(subject).to have_field(:password).of_type(String) }
  it { expect(subject).to have_field(:email).of_type(String) }
  it { expect(subject).to have_field(:dob).of_type(Date) }
  it { expect(subject).to have_field(:gender).of_type(String) }
  it { expect(subject).to have_field(:phone_number).of_type(String) }
  it { expect(subject).to have_field(:save_card_link_order_id).of_type(String) }
  it { expect(subject).to have_field(:source).of_type(String) }
  it { expect(subject).to have_field(:source_marketing).of_type(String) }
  it { expect(subject).to have_field(:adobe_adept_uuid).of_type(String) }

  it { expect(subject).to embed_many(:newsletters).of_type(Skeleton::Newsletter) }
  it { expect(subject).to embed_many(:terms_conditions).of_type(Skeleton::TermsConditions) }
  it { expect(subject).to embed_one(:adult).of_type(Skeleton::Adult) }
  it { expect(subject).to embed_many(:email_changes).of_type(Skeleton::EmailChange) }
  it { expect(subject).to embed_many(:personas).of_type(Skeleton::Persona) }
  it { expect(subject).to have_field(:social_uid).of_type(String) }
  it { expect(subject).to have_field(:social_account_link).of_type(String) }

  it 'should consider password, email and card as protected fields' do
    Skeleton::User.protected_attributes.should == \
      ActiveModel::MassAssignmentSecurity::BlackList.new(%w[id _id _type card password email salt sort_name])
  end

  context 'attr weak_password' do
    subject { Skeleton::User.new(weak_password: true) }

    its(:weak_password) { should be_true }
  end

  describe "index" do
    it { should have_index_for(email: 1).with_options(unique: true) }
    it { should have_index_for(external_id: 1).with_options(unique: true, background: false) }
    it { should have_index_for(cpf: 1).with_options(background: true) }
    it { should have_index_for(forgot_password_token: 1).with_options(background: false, sparse: true) }
    it { should have_index_for(verification_token: 1).with_options(unique: true, background: false, sparse: true) }
    it { should have_index_for(email_normalized: 1).with_options(background: true) }
    it { should have_index_for(name_normalized: 1).with_options(background: true) }
    it { should have_index_for(source: 1).with_options(background: true) }
    it { should have_index_for(social_uid: 1).with_options(background: true, unique: true, sparse: true) }
  end

  context "Validations" do
    it { should validate_presence_of(:name) }
    it { should validate_presence_of(:password) }
    it { should validate_presence_of(:email) }

    it { should validate_length_of(:name).with_maximum(80) }
    it { should validate_length_of(:email).with_maximum(70) }

    context 'email' do
      it 'should validate the uniqueness of email' do
        FactoryGirl.create(:user, email: 'me@me.com')
        user.email = 'me@me.com'
        user.should_not be_valid
        user.errors[:email][0].should == user.errors.generate_message(:email, :taken)
      end

      it "should validate uniqueness of email without case sensitive" do
        FactoryGirl.create(:user, email: 'me@me.com')
        user.email = 'ME@ME.COM'
        user.should_not be_valid
        user.errors[:email][0].should == user.errors.generate_message(:email, :taken)

        user.email = 'ME@me.COM'
        user.should_not be_valid
        user.errors[:email][0].should == user.errors.generate_message(:email, :taken)
      end

      it 'should validate the format of email' do
        user = FactoryGirl.build(:user, email: 'ee')
        user.should_not be_valid
        user.errors[:email].should_not be_empty
      end
    end

    context :gender do
      it 'should validate the gender' do
        user = FactoryGirl.build(:user, gender: 'N')
        user.should_not be_valid

        user = FactoryGirl.build(:user, gender: 'F')
        user.should be_valid
      end
    end

    context 'cpf' do
      it 'must be 11 digits' do
        user.cpf = '335.785.184-92'
        expect(user).to be_valid

        user.cpf = '1'*10
        expect(user).to be_invalid

        user.cpf = '1'*12
        expect(user).to be_invalid

        user.cpf = 'invalid'
        expect(user).to be_invalid
      end

      it 'verifies the checksum' do
        user.cpf = '335.785.184-92'
        expect(user).to be_valid

        user.cpf = '335.785.184-69'
        expect(user).to be_invalid
      end

      it 'is not possible to update CPF once set' do
        user = create(:user)

        expect {
          user.cpf = '21420445146'
          user.save!
          user.reload
        }.to change(user, :cpf).to('21420445146')

        expect {
          user.cpf = '48853156112'
          user.save!
          user.reload
        }.not_to change(user, :cpf)
      end
    end

    context 'password' do
      it 'rejects a short password' do
        user.password = 'a' * 7

        expect(user).not_to be_valid
        expect(user.errors[:password][0]).to eq 'A senha deve conter pelo menos 8 caracteres, incluindo letras e números.'
      end

      it 'rejects a large password missing number' do
        user.password = 'a' * 8

        expect(user).not_to be_valid
        expect(user.errors[:password][0]).to eq 'A senha deve conter pelo menos 8 caracteres, incluindo letras e números.'
      end

      it 'rejects a large password missing alpha' do
        user.password = '1' * 8

        expect(user).not_to be_valid
        expect(user.errors[:password][0]).to eq 'A senha deve conter pelo menos 8 caracteres, incluindo letras e números.'
      end

      it 'accepts a large password with number and alpha' do
        user.password = 'a' * 4 + '1' * 4
        expect(user).to be_valid
      end

      it 'accepts these kind of passwords' do
        user.password = 'pAssword$[]{}1'
        expect(user).to be_valid

        user.password = 'PASSWORD$[]{}-12*'
        expect(user).to be_valid

        user.password = 'PASSWORD12//'
        expect(user).to be_valid

        user.password = 'PASSWORD12\\'
        expect(user).to be_valid

        user.password = '123456^*ã'
        expect(user).to be_valid
      end

      it 'should save password encrypted with a salt' do
        mock_password 'p@ssw0rd', '123'
        FactoryGirl.create(:user, password: 'p@ssw0rd').password.should == '123'
      end

      it 'should not encrypt the password if it does not change' do
        user       = FactoryGirl.create(:user, password: 'p@ssw0rd')
        old_passwd = user.password
        user.email = 'd@do.com'
        user.save.should be_true
        user.password.should == old_passwd
      end

      it 'should not encrypt password if user uses iba1 authentication' do
        password = 'p@ssw0rd'
        FactoryGirl.create(:user, password: password, ess_imported_data: { }).password.should == password
      end

      it 'should not validate password if user uses iba1 authentication' do
        FactoryGirl.build(:user, password: '1', ess_imported_data: { }).should be_valid
      end

      context 'when weak_password is true' do
        let(:user) do
          user = FactoryGirl.build(:user, weak_password: true)
          user.password = '12345'
          user
        end

        it 'does not validate password format' do
          user.valid?
          user.errors[:password].should be_blank
        end
      end

      context 'when weak_password is false' do
        let(:user) do
          user = FactoryGirl.build(:user, weak_password: false)
          user.password = '12345'
          user
        end

        it 'does validate password format' do
          user.valid?
          user.errors[:password].should include('A senha deve conter pelo menos 8 caracteres, incluindo letras e números.')
        end
      end
    end
  end

  context "state" do
    it { should be_pending }
    it { should_not be_verified }

    context "unverified" do
      it { should have_field(:verification_token).of_type(String) }

      context "events signup" do
        it "should get a verification token" do
          user.signup
          user.verification_token.should_not be_nil
        end

        it "should transition to verified if the user has iba1 authentication" do
          user.ess_imported_data = { }
          user.signup!.should be_true
          user.should be_verified
        end

        it "should validate uniqueness of verification token" do
          user_1 = FactoryGirl.build(:user, password: 'p@ssw0rd')
          user_1.should_receive(:generate_token) do |transition|
            user_1.verification_token = "foo"
          end
          user_1.signup.should be_true
          user_1.should be_persisted

          user_2 = FactoryGirl.build(:user, password: 'p@ssw0rd')
          user_2.should_receive(:generate_token) do |transition|
            user_2.verification_token = "foo"
          end
          user_2.signup
          user_2.errors[:verification_token][0].should_not be_nil
        end

        it 'should generate a random token' do
          digest_mock = mock_token
          user.signup!
          user.verification_token.should == digest_mock
        end
      end
    end

    context "verified events verify" do
      before(:each) { user.signup! }

      it 'should transition from unverified' do
        user.should be_unverified
        user.verify.should be_true
        user.should be_verified
      end
    end

    context "save credit card details" do
      before(:each) { user.signup! }

      it 'should not transition from unverified to card_saved' do
        user.save_card.should be_false
      end

      it 'should not transition from verified to card_saved if billing details are not there' do
        user.verify!
        user.should be_verified
        user.save_card.should be_false
      end

      it 'should transition from verified to card_saved if card details are there' do
        user.verify!
        user.should be_verified
        user.address = FactoryGirl.build(:address)
        user.card    = FactoryGirl.build(:card)
        user.save!
        user.save_card.should be_true
        user.state.should == 'card_saved'
      end

      it 'should prevent card update on mass assignment' do
        user.verify!
        user.update_attributes card: FactoryGirl.build(:card)
        user.card.should be_nil
      end

      it 'transits from card_saved to verified without removing the card' do
        user.verify!
        user.card    = FactoryGirl.build(:card)
        user.save_card!

        user.delete_card!

        expect(user.card).to be_present
        expect(user.state).to eq 'verified'
      end

      it 'transits from verified to card_saved without removing the save_card_link' do
        user.verify!
        user.save_card_link_order_id = 111111
        user.card = FactoryGirl.build(:card)
        user.save_card!

        expect(user.save_card_link_order_id).to be_present
      end
    end
  end

  context "password_state" do
    it { should be_remember }
    it { should_not be_forgotten_password }

    context "forgotten_password" do
      it { should have_field(:forgot_password_token).of_type(String) }

      context "events forgot password click" do
        it "should get a forgot password token" do
          user.forgot_password_click
          user.forgot_password_token.should_not be_nil
        end

        it "should validate uniqueness of forgot password token" do
          user_1 = FactoryGirl.build(:user, password: 'p@ssw0rd')
          user_1.should_receive(:generate_forgot_password_token) do |transition|
            user_1.forgot_password_token = "foo"
          end
          user_1.forgot_password_click.should be_true
          user_1.should be_persisted

          user_2 = FactoryGirl.build(:user, password: 'p@ssw0rd')
          user_2.should_receive(:generate_forgot_password_token) do |transition|
            user_2.forgot_password_token = "foo"
          end
          user_2.forgot_password_click
          user_2.errors[:forgot_password_token][0].should_not be_nil
        end

        it 'should generate a random token' do
          random_mock = 'random_mock'
          digest_mock = 'digest_mock'
          SecureRandom.should_receive(:base64).and_return(random_mock)
          Digest.should_receive(:bubblebabble).with(random_mock).and_return(digest_mock)
          user = FactoryGirl.build(:user, password: 'p@ssw0rd')
          user.forgot_password_click
          user.forgot_password_token.should == digest_mock
        end
      end
    end

    context 'update user address' do
      it "should update a nested address attribute" do
        user = FactoryGirl.create(:user_with_billing_details)
        user.write_attributes({ 'address' => { 'city' => 'Rio-11' } })
        user.save!
        Skeleton::User.last.address.city.should == 'Rio-11'
      end
    end

    context 'email change' do
      before :each do
        Timecop.freeze
      end

      after :each do
        Timecop.return
      end

      it "should track changes to email address" do
        user['email'] = "oldemail@example.com"
        user.save.should be_true

        user.should have(1).email_changes
        user.email_changes.last.email.should == 'oldemail@example.com'

        user.email = "newemail@example.com"
        user.save.should be_true

        user.should have(2).email_changes
        user.email_changes.last.email.should == 'newemail@example.com'
        user.email_changes.last.changed_on.to_s.should == DateTime.now.utc.to_s
      end

      it "should move to unverified on email-change" do
        user.signup!
        user.verify!
        user.should be_verified

        user.email = "newemail@example.com"
        user.change_email.should be_true
        user.should be_unverified
      end

      it "should reset the verification token on email-change" do
        user.signup!
        initial_verification_token = user.verification_token
        user.email = "newemail@example.com"
        user.change_email.should be_true

        user.verification_token.should_not be_nil
        user.verification_token.should_not equal initial_verification_token
      end

      it "should move to remember password on email-change" do
        user.forgot_password_click
        user.email = "newemail@example.com"
        user.change_email.should be_true

        user.should be_remember
        user.forgot_password_token.should be_nil
      end

      it 'does not delete the saved card on email change' do
        user.signup!
        user.verify!

        user.card = FactoryGirl.build(:card)
        user.save!

        user.email = 'newemail@example.com'
        user.change_email

        expect(user.card_saved?).to be true
      end
    end

    context 'password reset' do
      it 'should transition from remember to forgotten password' do
        user.forgot_password_click

        user.should be_forgotten_password
      end

      it 'should transition from forgotten password to remember' do
        user.forgot_password_click

        user.password_reset.should be_true

        user.should be_remember
        user.forgot_password_token.should be_nil
      end

      context 'for iba1 user' do
        it 'should encrypt password for iba1 user' do
          user.forgot_password_click
          user.password          = 'p@ssw0rd'
          user.ess_imported_data = { }
          mock_password 'p@ssw0rd', 'encrypted_pwd'

          user.password_reset.should be_true

          user.should be_remember
          user.forgot_password_token.should be_nil
          user.password == 'encrypted_pwd'
        end
      end
    end
  end

  describe 'billing details' do
    it 'should have an address' do
      Skeleton::User.should embed_one(:address).of_type(Skeleton::Address)
    end

    context 'complete' do
      it "should return false if cpf and address are missing" do
        user.cpf     = nil
        user.address = nil
        user.billing_details_complete?.should be_false
      end

      it 'should return false if address is missing' do
        user.address = nil
        user.cpf     = '86173828057'
        user.billing_details_complete?.should be_false
      end

      it 'should return true if cpf is missing' do
        user = FactoryGirl.build(:user_with_billing_details, cpf: nil)
        user.billing_details_complete?.should be_false
      end

      it 'should return true if cpf and address are missing' do
        user = FactoryGirl.build(:user_with_billing_details)
        user.billing_details_complete?.should be_true
      end
    end
  end

  it 'sort name should be generated when the user is saved' do
    user.sort_name = 'to be modified'
    user.name      = 'ABC'
    user.save!
    user.sort_name.should == 'abc'
  end

  context 'Versioning' do
    it { should have_field(:version).of_type(Integer) }

    it 'should have a version when saved' do
      FactoryGirl.create(:user).version.should_not be_nil
    end

    it 'should update the version for any changes' do
      user        = FactoryGirl.create(:user_with_billing_details)
      old_version = user.version

      user.name = "myname"
      user.save

      user.version.should_not == old_version

      old_version       = user.version
      user.address.city = 'Booga'
      user.save

      user.version.should_not == old_version
    end

  end

  context 'ESS import' do
    it 'should save ESS imported data' do
      imported_data = {
        gender:              'M',
        rg:                  '1234567890',
        inscricao_estadual:  '1234567890',
        user_type:           'F',
        date_of_birth:       '28/02/1986',
        phone_number:        '1234-5678 ',
        branch_line_number:  '51',
        cellphone_number:    '12345-6789',
        deactivated:         false,
        deactivation_date:   DateTime.parse('2012/06/06').to_s,
        last_version_id:     '1',
        version:             '1',
        cnpj:                '46186202000170',
        cellphone_area_code: '123',
        simplificado:        true,
      }

      user = FactoryGirl.build(:user, ess_imported_data: imported_data)
      user.save

      saved_user = Skeleton::User.last
      imported_data.keys.each do |field|
        saved_user.ess_imported_data[field].should == user.ess_imported_data[field]
      end
    end
  end

  context 'update user profile' do
    it 'should save updated by field in user' do
      user = FactoryGirl.build :user, updated_by: 'User'
      user.save.should be_true
      Skeleton::User.last.updated_by.should == 'User'
    end
  end

  context 'searchable' do
    %w[
      verification_token forgot_password_token cpf external_id gender email
      created_at name newsletters.accepted address.state source source_marketing social_uid adobe_adept_uuid
    ].each do |field_name|
      it "is searchable by #{field_name}" do
        described_class._searchable_parameters.keys.map(&:to_s).should include(field_name)
      end
    end
  end

  describe "#unverified_assine_user?" do
    it "returns false if source not 'assine'" do
      user = FactoryGirl.build(:user, source: 'some source')
      user.unverified_assine_user?.should be_false
    end

    it "returns false if 'verified'" do
      user = FactoryGirl.build(:user, state: :verified)
      user.unverified_assine_user?.should be_false
    end

    it "returns true if source 'assine' and unverified status" do
      source = Skeleton::User::ASSINE
      user = FactoryGirl.build(:user, source: source, state: :unverified)
      user.unverified_assine_user?.should be_true
    end

    it "returns true if source an assine partnership and unverified status" do
      source = Skeleton::User::ASSINE_PARTNERS_SOURCES.sample(1).first
      user = FactoryGirl.build(:user, source: source, state: :unverified)
      user.unverified_assine_user?.should be_true
    end
  end

  describe '.find_by_email' do
    it 'returns nil if email blank' do
      Skeleton::User.find_by_email(nil).should be_nil
    end

    it 'returns user by email' do
      user = FactoryGirl.create(:user, email: "john@example.org")
      Skeleton::User.find_by_email("JOHN@example.org").should == user
    end
  end

  describe '#valid_password?' do
    subject(:user) { FactoryGirl.create(:user, password: "teste@123") }

    it 'returns false if password is blank' do
      user.password = ''
      user.valid_password?('').should be_false
    end

    it 'returns false if provided password is blank' do
      user.valid_password?('').should be_false
    end

    it 'returns true if password matches' do
      user.valid_password?("teste@123").should be_true
    end

    it 'returns false if password do not match' do
      user.valid_password?("secret").should be_false
    end
  end

  describe 'temporary_password' do
    let(:redis) { MockRedis.new }
    let(:temp_password) {"temporary@123"}
    let(:temp_password_hash) { 'fdsf1233232few'}
    let(:user) { FactoryGirl.create(:user, password: "teste@123") }

    subject { user.temporary_password(temp_password) }
    before do
      allow(BCrypt::Password).to receive(:create) { temp_password_hash }
      allow(Skeleton.config).to receive(:redis) { redis }
    end

    it 'should save user temporary password on redis with ttl' do
      expect(Skeleton.config).to receive(:[]=).with("temporary_password:#{user.id}", temp_password_hash)
      expect(Skeleton.config.redis).to receive(:expire).with("temporary_password:#{user.id}", 600)

      subject
    end
  end

  describe 'valid_temporary_password?' do
    let(:user) { FactoryGirl.create(:user, password: "teste@123") }

    subject { user.valid_temporary_password?(password) }

    context "when password is blank" do
      let(:password) { '' }

      it "should be false" do
        subject.should be_false
      end
    end

    context "when password is not blank" do
      let(:password) { "temporary@123" }

      context "when temporary_password is not set" do
        it "should be false" do
          subject.should be_false
        end
      end

      context "when temporary_password is set" do
        before { user.temporary_password(password) }

        context "when password is invalid" do
          subject { user.valid_temporary_password?('teste@123') }

          it "should be false" do
            subject.should be_false
          end
        end

        context "when password is valid" do
          it "should be true" do
            subject.should be_true
          end
        end
      end
    end
  end

  describe '#add_terms_conditions' do
    before { user.save! }

    it 'adds a new terms and conditions' do
      terms = Skeleton::TermsConditions.new(source: 'iba', type: 'registration')

      expect {
        user.add_terms_condition(terms)
        user.reload # check if persisted
      }.to change { user.terms_conditions.size }.by(1)
    end

    it 'does not add duplicated terms conditions' do
      terms = Skeleton::TermsConditions.new(source: 'iba', type: 'registration')

      expect {
        user.add_terms_condition(terms)
        user.add_terms_condition(terms)
      }.to change { user.terms_conditions.size }.by(1)
    end

    it 'does not add invalid terms conditions' do
      terms = Skeleton::TermsConditions.new(source: 'iba', type: '')

      user.add_terms_condition(terms)
      user.reload

      expect(user.terms_conditions).to be_empty
    end
  end

  describe '#card_saved?' do
    it 'returns true when the user has a card' do
      user.card = FactoryGirl.build(:card)

      expect(user.card_saved?).to be true
    end

    it 'returns false when the user does not have a card' do
      expect(user.card_saved?).to be false
    end
  end
end
