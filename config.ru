require 'bundler'
Bundler.require
require 'newrelic_rpm'

$: << File.dirname(__FILE__)

if ENV['RACK_ENV'] =~ /development/
  require 'new_relic/rack/developer_mode'
  use NewRelic::Rack::DeveloperMode
end

use NewRelic::Rack::AgentHooks
#use SinatraRest::AppLogger, File.expand_path(File.dirname(__FILE__))

require 'skeleton'

if Skeleton.config.protected?
  #use SinatraRest::AuthBasic, Skeleton.config.auth
end

if Skeleton.config.cache?
  #use SinatraRest::CacheControl, Skeleton.config.expiry
end

run Rack::URLMap.new Skeleton.route_map
