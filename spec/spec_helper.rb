require 'bundler/setup'
require 'active_model'
#Bundler.require :default, :test

#require 'ci_tasks/simplecov'
ENV['RACK_ENV'] ||= 'test'
require 'sinatra'
#require 'pry'
require 'vcr'
require 'factory_girl'

spec_root = File.expand_path(File.dirname(__FILE__))
$: << spec_root
$: << File.expand_path(File.join(File.dirname(__FILE__), '..'))

Sinatra::Base.set :environment, :test

require File.join(File.dirname(__FILE__), '..', 'skeleton')

Dir[File.join(spec_root, "support/**/*.rb")].each { |f| require f }

FactoryGirl.definition_file_paths = [File.join(File.dirname(__FILE__), 'factories')]
FactoryGirl.find_definitions

#require 'iba_config/testing'

RSpec.configure do |config|
  #config.include Mongoid::Matchers
  #config.include Sinatra::TestHelpers
  config.include FactoryGirl::Syntax::Methods

  config.before(:suite) do
    DatabaseCleaner.strategy = :truncation
  end

  config.before(:each) do
    DatabaseCleaner.start
  end

  config.after(:each) do
    DatabaseCleaner.clean
  end
end
