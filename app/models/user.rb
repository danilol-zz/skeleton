class Skeleton::User
  include Mongoid::Document
  include Mongoid::Timestamps
  include Mongoid::Validations
  include MongoidAmplified::Versioning
  include MongoidAmplified::Searchable
  include MongoidAmplified::Pagination
  include MongoidAmplified::Normalized

  FORMAT_EMAIL = /\A([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\Z/i

  ASSINE = 'assine'
  ASSINE_PARTNERS_SOURCES = Skeleton.config.redis.smembers('assine:partners:sources')

  field :name,                    type: String
  field :email,                   type: String
  field :dob,                     type: Date
  field :gender,                  type: String
  field :phone_number,            type: String
  field :password,                type: String
  field :verification_token,      type: String
  field :forgot_password_token,   type: String
  field :save_card_link_order_id, type: String
  field :cpf,                     type: String
  field :sort_name,               type: String
  field :salt,                    type: String
  field :external_id,             type: Integer
  field :crp_id,                  type: String
  field :updated_by,              type: String, default: ''
  field :source,                  type: String
  field :source_marketing,        type: String
  field :social_uid,              type: String
  field :social_account_link,     type: String
  field :adobe_adept_uuid,        type: String

  normalized :email, :name

  searchable :verification_token, :forgot_password_token, :cpf,
             :external_id, :gender, :created_at, :source, :source_marketing,
             :social_uid, :adobe_adept_uuid
  searchable :email, normalized: true
  searchable :name, like: true, normalized: true
  searchable :newsletters_opted, embedded_as: :newsletters, field: :accepted
  searchable :address_state, embedded_as: :address, field: :state

  embeds_one :address, class_name: 'Skeleton::Address'
  embeds_one :card, class_name: 'Skeleton::Card', inverse_of: :user
  embeds_one :ess_imported_data, class_name: 'Skeleton::EssImportedData'
  embeds_one :adult, class_name: 'Skeleton::Adult'

  embeds_many :terms_conditions, class_name: 'Skeleton::TermsConditions'
  embeds_many :newsletters, class_name: 'Skeleton::Newsletter'

  embeds_many :email_changes, class_name: 'Skeleton::EmailChange'
  embeds_many :rollback_tokens, class_name: 'Skeleton::RollbackToken'

  embeds_many :personas, class_name: 'Skeleton::Persona'

  attr_accessor :weak_password

  attr_protected :card, :email, :password, :salt, :sort_name

  validates_uniqueness_of :email
  validates_uniqueness_of :social_uid, allow_blank: true

  validates_with ::Validators::Password, if: :use_format_validator?

  validates :name, presence: true, length:  { maximum: 80 }
  validates :email, presence: true
  validates :email, length: { maximum: 70 }, format: FORMAT_EMAIL, allow_blank: true
  validates_presence_of :password
  validates :cpf, numericality: true, length: { is: 11 }, allow_blank: true, cpf: true
  validates_inclusion_of :gender, in: ['M', 'F'], allow_nil: true
  validates :dob, date: true

  before_save :encrypt_password!, if: :password_changed?
  before_save :generate_sort_name!
  before_save :track_email_change!, if: :email_changed?
  before_validation { |user| user.email.downcase! if user.email.present? }

  before_save :set_adult_info

  index( { email: 1 },                 { unique: true })
  index( { external_id: 1 },           { unique: true, background: false })
  index( { cpf: 1 },                   { background: true })
  index( { forgot_password_token: 1 }, { background: false, sparse: true })
  index( { verification_token: 1 },    { unique: true, background: false, sparse: true })
  index( { created_at: 1, name: 1 },   { background: true })
  index( { name: 1 },                  { background: true })
  index( { email: 1, sort_name: 1 },   { background: true })
  index( { name: 1, sort_name: 1 },    { background: true })
  index( { created_at: 1 },            { background: true })
  index( { source: 1 },                { background: true })
  index( { social_uid: 1 },            { background: true, unique: true, sparse: true })

  state_machine :state, initial: :pending do
    before_transition any => :unverified, do: :generate_token

    state all do
      transition to: :unverified, on: :apply_email

      def generate_token(transition)
        self.verification_token = generate_digest_token
      end
    end

    state :pending do
      transition to: :verified, on: :signup, if: :iba1_user?
      transition to: :unverified, on: :signup
    end

    state :unverified do
      validates_uniqueness_of :verification_token
    end

    state :card_saved
    state :verified

    event :verify do
      transition to: :verified
    end

    event :save_card do
      transition verified: :card_saved, if: :billing_details_complete? && :card_present?
    end

    event :delete_card do
      # This transition changes the state to `verified` without any verification,
      # because the user's state can be:
      # - `card_saved` if it was added via webstore or any other source if it has
      # email verification.
      # - `unverified` if it was added via iba clube, since there is no verification
      # when the user is created.
      transition to: :verified
    end
  end

  state_machine :password_state, initial: :remember do
    before_transition remember: :forgotten_password, do: :generate_forgot_password_token
    before_transition forgotten_password: :remember, do: :remove_forgot_password_token

    state :remember do
      transition to: :forgotten_password, on: :forgot_password_click

      def generate_forgot_password_token(transition)
        self.forgot_password_token = generate_digest_token
      end
    end

    state :forgotten_password do
      validates_uniqueness_of :forgot_password_token

      def remove_forgot_password_token(transition)
        self.forgot_password_token = nil
      end
    end

    event :password_reset do
      transition to: :remember
    end
  end

  def self.find_by_email(email)
    where(email_normalized: email.downcase).first if email
  end

  # Public: assigning user CPF.
  #
  # Once set the CPF is readonly.
  def cpf=(value)
    write_attribute(:cpf, strip_cpf(value)) if new_record? || self.cpf.blank?
  end

  def valid_password?(password)
    return false if self.password.blank? || password.blank?
    BCrypt::Password.new(self.password) == "#{self.salt}:#{password}"
  end

  def valid_temporary_password?(temporary_password)
    stored_temporary_password = Skeleton.config["temporary_password:#{self.id}"]
    return false if temporary_password.blank? || stored_temporary_password.blank?

    BCrypt::Password.new(stored_temporary_password) == "#{self.salt}:#{temporary_password}"
  end

  # Public: adds terms conditions.
  #
  # It ensures a idempontent operation, if there is already a terms condition with
  # same source and type, it does not add again.
  #
  # Returns the list of terms conditions.
  def add_terms_condition(value)
    same_source_and_value = Proc.new { |tc| tc.source == value.source && tc.type == value.type }

    if self.terms_conditions.none?(&same_source_and_value)
      self.terms_conditions << value
    end

    self.terms_conditions
  end

  # Public: checks if the user has a saved card.
  #
  # Returns true if a card is present, false otherwise.
  def card_saved?
    self.card.present?
  end

  def links
    links = []
    links << { rel: 'reset_forgotten_password', href: reset_forgotten_password_href } if forgotten_password?
    links << { rel: 'generate_forgot_password_token', href: forgot_password_token_href } if remember?
    links << { rel: 'verify', href: verify_href } if unverified?
    links << { rel: 'set_adult', href: set_adult_href }
    links << { rel: 'change_email', href: change_email_href }
    links << { rel: 'rollback_changed_email', href: rollback_changed_email_href }
    links << { rel: 'change_password', href: change_password_href }
    links << { rel: 'save_card', href: save_card_href }
    links << { rel: 'delete_card', href: delete_card_href }
    links << { rel: 'card', href: card_href }
    links << { rel: 'self', href: self_href }
    links << { rel: 'newsletters', href: add_newsletter_href }
    links << { rel: 'terms_conditions', href: add_terms_conditions_href }
    links << { rel: 'verify_password', href: verify_password_href }
    links << { rel: 'generate_temporary_password', href: generate_temporary_password_href }
    links
  end

  def billing_details_complete?
    self.cpf.present? && self.address.present?
  end

  def missing_billing_details?
    !billing_details_complete?
  end

  def card_present?
    card.present?
  end

  def self_href
    "/user/#{_id}"
  end

  def is_adult?
    self.adult.confirmed rescue false
  end

  def iba1_user?
    ess_imported_data.present?
  end

  def change_email
    self.apply_email!
    self.password_reset!
    true
  end

  # Public: Rolls an email account back to the one that matches the given token.
  #
  # Keys points
  #
  #   * The token must be fresh. See `Skeleton::RollbackToken#expired?` for more
  #   information.
  #
  #   * After an email is rolled back, all the subsequent tokens (if they exist)
  #   will be expired, whereas prior tokens remains at hand. It ensures two
  #   important things:
  #
  #     1) The user who issued the very first email change will always be able to
  #     recover the original email back, even that many other email changes were
  #     performed in the meanwhile.
  #
  #     2) Tokens that were generated after an email rollback will not succeed on
  #     rolling their corresponding emails back. In other words, older tokens have
  #     precedence over new created tokens.
  #
  # token - A digest that correspond to an email that is willing to be rolled
  #         back.
  #
  # Example
  #
  #    user.email
  #    # => 'intruder@iba.com'
  #    user.rollback_changed_email('invalid token')
  #    # => nil
  #    user.rollback_changed_email('valid token')
  #    # => true
  #    user.email
  #    # => 'john@iba.com'
  def rollback_changed_email(token)
    rollback_token = rollback_tokens.where(:token => token).first

    if rollback_token.present? && !rollback_token.expired?
      rollback_token.expire!
      rollback_tokens.expire_subsequent_tokens!(rollback_token)

      @is_rolling_an_email_back = true
      self.email = rollback_token.rollback_to
      self.save
    end
  end

  def set_weak_password(new_password)
    self.weak_password = true
    self.password = new_password
  end

  def unverified_assine_user?
    (ASSINE_PARTNERS_SOURCES + [ASSINE]).include?(source) && unverified?
  end

  def temporary_password(temp_password)
    Skeleton.config["temporary_password:#{self.id}"] = BCrypt::Password.create("#{self.salt}:#{temp_password}")
    Skeleton.config.redis.expire("temporary_password:#{self.id}", 600)
  end

  private

  def generate_digest_token
    Digest.bubblebabble(SecureRandom.base64)
  end

  def use_format_validator?
    not(iba1_user? or weak_password)
  end

  def new_iba1_user?
    new_record? and iba1_user?
  end

  def reset_forgotten_password_href
    "/user/reset_forgotten_password/#{self.forgot_password_token}"
  end

  def add_newsletter_href
    "/user/#{self._id}/newsletters"
  end

  def add_terms_conditions_href
    "/user/#{self._id}/terms_conditions"
  end

  def forgot_password_token_href
    "/user/generate_forgot_password_token"
  end

  def generate_temporary_password_href
    "/user/#{self._id}/generate_temporary_password"
  end

  def verify_href
    "/user/verify/#{self.verification_token}"
  end

  def delete_card_href
    "/user/#{self._id}/card"
  end

  def save_card_href
    "/user/#{self._id}/card"
  end

  def set_adult_href
    "/user/set_adult/#{self._id}"
  end

  def change_email_href
    "/user/change_email/#{self._id}"
  end

  def rollback_changed_email_href
    "/user/rollback_changed_email/#{self._id}"
  end

  def change_password_href
    "/user/#{self.id}/change_password"
  end

  def card_href
    "/user/#{self._id}/card"
  end

  def verify_password_href
    "/user/#{self._id}/verify_password"
  end

  def generate_sort_name!
    self.sort_name = name.downcase unless name.nil?
  end

  def encrypt_password!
    if !new_iba1_user? && !salt_changed?
      self.salt     = "#{SecureRandom.uuid}#{Time.now.to_i}".hash
      self.password = BCrypt::Password.create("#{self.salt}:#{self.password}")
    end
  end

  def track_email_change!
    self.email_changes << Skeleton::EmailChange.new(email: self.email, changed_on: DateTime.now.utc)
  end

  def set_adult_info
    unless self.adult
      self.adult = Skeleton::Adult.new
    end
  end

  def strip_cpf(cpf)
    cpf.gsub(/[\.-]/, '') if cpf.present?
  end
end
