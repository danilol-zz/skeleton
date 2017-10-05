class Skeleton::Controllers::User < Sinatra::Base
  set :vendor, 'iba.skeleton.user'

  #register SinatraRest::MongoApp

  get '/:id' do
    vnd_type

    logger.info "looking for '#{params[:id]}'"

    @user = Skeleton::User.find(params[:id])

    etag @user.etag

    render :rabl, :user, format: 'json'
  end

  post '/' do
    vnd_type

    request_body = parse_json
    user = Skeleton::User.new parse_hash(Skeleton::User, request_body.dup)
    user.password = request_body['password']
    user.salt = request_body['salt']
    user.email = request_body['email']

    unless user.valid?
      logger.info "errors encountered #{user.errors.messages}"
      @user = user
      halt 422, render(:rabl, :user, format: 'json')
    end

    ensure_external_id_for user
    user.signup!

    created user.self_href
  end

  put '/set_adult/:user_id' do
    vnd_type

    user = Skeleton::User.find(params[:user_id]) rescue nil
    logger.info "setting adult confirmed for user '#{user}'"

    status 401 and return if (user.nil?)

    user.adult = Skeleton::Adult.new unless user.adult.nil?
    user.adult.confirmed = true

    user.save!
    ok
    { }.to_json
  end

  put '/change_email/:user_id' do
    vnd_type

    user = Skeleton::User.find(params[:user_id])

    logger.info "changing email for user with email '#{user.email}'"

    user_params = parse_json

    if user.email == user_params['email']
      user.errors.add('email', I18n.t('mongoid.errors.models.skeleton/user.attributes.email.same_as_current'))
      unprocessable_entity(errors: user.errors)
    end

    user_email_change = Skeleton::UserEmailChange.new(user)
    user_email_change.change_email(user_params['email'])

    unless user_email_change.user.valid?
      unprocessable_entity(errors: user_email_change.user.errors)
    end

    ok
    { rollback_token: user_email_change.rollback_token }.to_json
  end

  put '/rollback_changed_email/:user_id' do
    vnd_type

    @user = Skeleton::User.find(params[:user_id])

    logger.info "rolling changed user email back from '#{@user.email}' to '#{@user.email_changes.second}'"

    rollback_params = parse_json

    if @user.rollback_changed_email(rollback_params['rollback_token'])
      render :rabl, :user, format: 'json'
    else
      halt(422)
    end
  end

  put '/:id/change_password' do
    vnd_type 'user.change_password'

    user = Skeleton::User.find(params[:id])
    passwords = parse_json

    if user.valid_password?(passwords['current_password'])
      user.password = passwords['new_password']

      if user.save
        ok
      else
        halt(422, { resource: { errors: user.errors.messages } }.to_json)
      end
    else
      user.errors.add('password', I18n.t('mongoid.errors.models.user.attributes.password.incorrect'))
      halt(422, { resource: { errors: user.errors } }.to_json)
    end
  end

  put '/:id' do
    vnd_type

    request_data = parse_json
    request_data.delete('adult')

    user = Skeleton::User.find(params[:id])
    logger.info "updating for '#{request_data.except('password')}'"

    if request_data['password'].present?
      user.password = request_data['password']
      user.salt = request_data['salt'] if request_data['salt'].present? && user.iba1_user?
    end

    unless user.update_attributes(parse_hash(Skeleton::User, request_data))
      logger.info "errors encountered #{user.errors.messages}"
      @user = user
      halt 422, render(:rabl, :user, format: 'json')
    end

    ok
  end

  post '/generate_forgot_password_token' do
    content_type :json

    user_params = JSON.parse(request.body.read.to_s)
    status 400 and return if !(user_params['email'].present?)

    user = Skeleton::User.find_by_email(user_params['email'])

    unprocessable_entity(I18n.t 'forgot_password_token') and return unless user.present?

    user.forgot_password_click!

    headers['Location'] = user.self_href
    status 204
  end

  post '/:id/generate_temporary_password' do
    user = Skeleton::User.find(params[:id])
    halt 404 and return if user.nil?

    temp_password = random_temporary_password
    user.temporary_password(temp_password)

    headers['Location'] = temp_password
    status 201
  end

  put '/verify/:verification_token' do
    user = Skeleton::User.where(verification_token: params[:verification_token]).first

    status 401 and return if user.nil?
    status 304 and return if user.verified?

    user.verify!

    ok
    {}.to_json
  end

  put '/reset_forgotten_password/:forgot_password_token' do
    user = Skeleton::User.where(forgot_password_token: params[:forgot_password_token]).first

    status 401 and return if user.nil?

    user_params = parse_json
    user.password = user_params['password']
    user.password_reset!

    ok
    {}.to_json
  end

  post '/auth' do
    content_type :json
    user_params = parse_json

    user = Skeleton::User.find_by_email(user_params['email']) or not_authorized

    # User authentication with temporary_password for callcenter
    if user.valid_temporary_password?(user_params['password'])
      headers['Location'] = user.self_href
      halt(200, {temporary_login: true}.to_json)
    end

    # Unverified assine users must have its email/password validated by
    # assine authentication to be verified, in order to follow the normal
    # user registration.
    if user.unverified_assine_user?
      assine_auth_response = assine_auth(user.email, user_params['password'])
      not_authorized unless assine_auth_response.success?

      # mark password as weak, since it is not compliant with iba's password
      # policy and set user as a verified one
      user.set_weak_password(user_params['password'])
      user.verify!

      if user.save
        headers['Location'] = user.self_href
        return ok
      end

    # default authentication
    elsif user.valid_password?(user_params['password'])
      headers['Location'] = user.self_href
      return ok
    end

    not_authorized
  end

  post '/:id/card' do
    content_type :json
    user = Skeleton::User.find(params[:id])
    conflict(errors: I18n.t('card.already_exists')) if user.card_present?

    card = Skeleton::Card.new(parse_json)
    bad_request(errors: card.errors) unless card.valid?

    user.card = card
    user.save!

    ok
    {}.to_json
  end

  delete '/:id/card' do
    user = Skeleton::User.find(params[:id])
    bad_request(errors: I18n.t('card.no_saved_card')) unless user.card_saved?

    user.card.delete

    # Call the state machine event even if the toggle is enabled
    # to ensure users to return to the `verified` state.
    user.delete_card!

    ok
    {}.to_json
  end

  get '/:id/card' do
    content_type :json
    user = Skeleton::User.find(params[:id])
    bad_request unless user.card_saved?

    etag user.etag

    @card = user.card

    render :rabl, :card, format: 'json'
  end

  get '/:id/newsletters' do
    content_type :json
    user = Skeleton::User.find(params[:id])

    status not_found and return if user.nil?

    @newsletters = user.newsletters
    render :rabl, :newsletters , format: 'json'
  end

  post '/:id/newsletters' do
    content_type :json
    request_data = parse_json

    user = Skeleton::User.find(params[:id])

    newsletter = user.newsletters.where(type: request_data[:type]).first_or_initialize
    newsletter.attributes = request_data
    user.newsletters << newsletter if newsletter.new_record?

    if newsletter.valid?
      user.save!
      ok
    else
      @newsletters = user.newsletters
      halt(422, render(:rabl, :newsletters, format: 'json'))
    end
  end

  put '/:id/newsletters' do
    vnd_type

    user = Skeleton::User.find(params[:id])
    request_data = parse_json

    index = user.newsletters.find_index { |n| n.type == request_data['type'] }

    status bad_request and return if (user.nil? || index.blank?)
    newsletter = Skeleton::Newsletter.new request_data

    unless newsletter.valid?
      user.newsletters[index] = newsletter
      logger.info "errors encountered #{user.errors.messages}"
      @newsletters = user.newsletters
      halt 422, render(:rabl, :newsletters, format: 'json')
    end

    user.newsletters[index].update_attributes parse_hash(Skeleton::Newsletter, request_data)
    user.save!
    ok
  end

  get '/:id/terms_conditions' do
    content_type :json
    user = Skeleton::User.find(params[:id])

    @terms_conditions = user.terms_conditions

    render :rabl, :terms_conditions , format: 'json'
  end

  post '/:id/terms_conditions' do
    content_type :json
    user = Skeleton::User.find(params[:id])

    terms_condition = Skeleton::TermsConditions.new(parse_json)
    user.add_terms_condition(terms_condition)

    if user.valid?
      ok
    else
      @terms_conditions = user.terms_conditions
      halt 422, render(:rabl, :terms_conditions, format: 'json')
    end
  end

  get '/:id/verify_password' do
    content_type :json
    user = Skeleton::User.find(params[:id])
    user.valid_password?(params['password']) ? ok : status(bad_request)
  end

  private

  def ensure_external_id_for(user)
    external_id = user.external_id || next_external_id
    #raise SinatraRest::HttpStatusError.new(status: 409, errors: I18n.t('external_id.present')) if user_exists_for?(external_id)
    user.external_id = external_id
  end

  def user_exists_for?(external_id)
    Skeleton::User.where(external_id: external_id).exists?
  end

  def next_external_id
    Skeleton.config.redis.incr(:last_ess_user_id)
  end

  # Private: authenticate user at 'assine'
  # It request to subscriptions because there is already an endpoint to verify
  # credentials at 'assine', used for readers to perform authentication and
  # get its subscriptions in one request
  def assine_auth(user, passwd)
    SubscriptionsClient::Subscriptions.relations.assine_auth.post do |req|
      req.body = {email: user, password: passwd}.to_json
    end
  end

  def not_authorized
    halt 401, I18n.t('auth')
  end

  def random_temporary_password
    range = [*'0'..'9', *'a'..'z', *'A'..'Z']
    Array.new(8){range.sample}.join
  end
end
