ENV['RACK_ENV'] ||= 'development'

$LOAD_PATH << 'app'

require 'digest/bubblebabble'
require 'bcrypt'

#require File.join(File.dirname(__FILE__), 'config', 'initializers', 'iba_config')
require File.join(File.dirname(__FILE__), 'config', 'initializers', 'mongoid')
#require File.join(File.dirname(__FILE__), 'config', 'initializers', 'i18n')

Dir[File.join(File.dirname(__FILE__), 'config', 'initializers', '*_client.rb')].each do |iba_client|
  require iba_client
end

Bundler.require
Rabl.register!

module Validators
  Dir['./app/validators/*.rb'].each { |validator| require validator }
end

module Skeleton
  Dir['./app/*.rb'].each { |lib| require lib }

  Dir[File.join(File.dirname(__FILE__), 'app', 'models/*.rb')].each do |f|
    autoload File.basename(f, '.rb').camelize.to_sym, f
  end

  Dir['./app/parsers/*.rb'].each { |parser| require parser }

  module Serializers
    Dir[File.join(File.dirname(__FILE__), 'app', 'serializers/*.rb')].each { |controller| require controller }
  end

  module Controllers
    Dir['./app/controllers/*.rb'].each { |controller| require controller }
  end


  def self.route_map
    map = {
      '/'                      => Skeleton::App,
      #'/search'                => Skeleton::Controllers::Search,
      '/user'                  => Skeleton::Controllers::User,
      #'/social'                => Skeleton::Controllers::Social,
      #'/reader_session_tokens' => Skeleton::Controllers::ReaderSessionToken,
      #'/admin'                 => Skeleton::Controllers::Admin,
      #'/callcenter_user'       => Skeleton::Controllers::CallcenterUser,
      #'/health_check'          => IbaConfig::HealthCheck::VersionedApp.new({ redis: IbaConfig::HealthCheck::Redis.new(Skeleton.config.redis), mongo: IbaConfig::HealthCheck::Mongo.new, })
    }

    #map.merge!({
      #'/everything' => Skeleton::Controllers::DeleteAll,
      #'/seed'       => Skeleton::Controllers::Seed
    #}) if ENV['RACK_ENV'] =~ /development|test|cucumber/

    map
  end
end
